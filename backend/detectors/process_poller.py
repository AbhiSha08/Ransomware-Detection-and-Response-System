"""
backend/detectors/process_poller.py
=====================================
Asynchronous system process telemetry collector for the RDRS detection engine.

This module implements a non-blocking polling loop using ``psutil`` to capture
point-in-time snapshots of all running processes at configurable intervals.
Telemetry is persisted to the ``process_snapshots`` table and forwarded to
the scoring engine for behavioral analysis.

Key Design Choices:
  - The poll loop is an asyncio task, coordinated by ``asyncio.sleep()``.
  - CPU percent measurement uses a two-call pattern (``interval=None`` on the
    first call, then read after a short pause) to avoid blocking the event loop.
  - All ``psutil`` exceptions (``NoSuchProcess``, ``AccessDenied``,
    ``ZombieProcess``) are silently swallowed per-process — a single inaccessible
    process must never crash the poller.
  - High-risk processes (from config) are flagged immediately on detection.
  - Disk write bytes are recorded as ``io_counters().write_bytes`` where available.

Process Snapshot Data Collected:
  PID, process name, CPU%, memory RSS (MB), disk write bytes (cumulative),
  executable path, parent PID, parent name, command line, high-risk flag.

Usage:
    from backend.detectors.process_poller import ProcessPoller

    poller = ProcessPoller(event_queue=scoring_engine.process_queue)
    await poller.start()
    ...
    await poller.stop()
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import psutil
from loguru import logger

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.database.models import ProcessSnapshot
from backend.database.session import get_async_db_session

if TYPE_CHECKING:
    pass

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Bytes → Megabytes conversion factor.
_BYTES_TO_MB: float = 1.0 / (1024.0 * 1024.0)

#: Maximum number of process snapshots buffered in the outgoing queue.
_QUEUE_MAX_SIZE: int = 2048

#: Seconds to wait for initial CPU percent accumulation (non-blocking in async).
_CPU_INTERVAL_SECONDS: float = 0.1


# ===========================================================================
# Data Transfer Objects
# ===========================================================================


@dataclass(slots=True)
class RawProcessSnapshot:
    """
    Lightweight DTO carrying process telemetry from the polling loop to the
    scoring engine. All fields are primitive types for fast serialization.

    Attributes:
        timestamp:        UTC datetime of the snapshot.
        pid:              Operating system process ID.
        process_name:     Process executable name.
        cpu_percent:      CPU utilization at snapshot time.
        memory_mb:        Resident set size in megabytes.
        disk_write_bytes: Cumulative disk write bytes since process start.
        exe_path:         Absolute path to the executable.
        parent_pid:       Parent process ID; None for root processes.
        parent_name:      Parent process name (denormalized).
        cmdline:          Space-joined command line arguments.
        is_flagged:       True if process name matches the high-risk list.
        flag_reason:      Reason string if flagged; None otherwise.
    """

    timestamp: datetime
    pid: int
    process_name: str
    cpu_percent: float
    memory_mb: float
    disk_write_bytes: int
    exe_path: str | None
    parent_pid: int | None
    parent_name: str | None
    cmdline: str | None
    is_flagged: bool
    flag_reason: str | None


@dataclass
class PollerStats:
    """
    Running statistics for the process poller, used for health monitoring.

    Attributes:
        poll_cycles:       Number of completed poll cycles.
        total_snapshots:   Total process snapshots captured across all cycles.
        total_persisted:   Snapshots successfully written to the database.
        total_errors:      Processes that raised errors during collection.
        flagged_processes: Cumulative count of high-risk process detections.
    """

    poll_cycles: int = 0
    total_snapshots: int = 0
    total_persisted: int = 0
    total_errors: int = 0
    flagged_processes: int = 0


# ===========================================================================
# Snapshot Collection Helper
# ===========================================================================


def _collect_process_snapshot(
    proc: psutil.Process,
    high_risk_names: frozenset[str],
    whitelist_names: frozenset[str],
) -> RawProcessSnapshot | None:
    """
    Extract telemetry from a single ``psutil.Process`` object.

    Handles all psutil exceptions gracefully — returns ``None`` if the process
    terminates or becomes inaccessible during collection.

    Args:
        proc:             The psutil Process object to interrogate.
        high_risk_names:  Lowercase process names that are considered high-risk.
        whitelist_names:  Lowercase process names that are always trusted.

    Returns:
        RawProcessSnapshot | None: Populated snapshot DTO, or None on failure.
    """
    try:
        # Batch fetch with oneshot() for efficiency (single kernel call)
        with proc.oneshot():
            pid = proc.pid
            name = proc.name()
            name_lower = name.lower().removesuffix(".exe")

            # CPU percent — uses cached value from prior call on same process object
            cpu = proc.cpu_percent(interval=None)

            # Memory RSS
            mem_info = proc.memory_info()
            memory_mb = mem_info.rss * _BYTES_TO_MB

            # Disk I/O (may raise AccessDenied on some platforms)
            disk_write_bytes = 0
            try:
                io = proc.io_counters()
                disk_write_bytes = io.write_bytes
            except (psutil.AccessDenied, AttributeError):
                pass

            # Executable path
            exe_path: str | None = None
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Parent process
            parent_pid: int | None = None
            parent_name: str | None = None
            try:
                parent = proc.parent()
                if parent:
                    parent_pid = parent.pid
                    parent_name = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Command line
            cmdline_str: str | None = None
            try:
                parts = proc.cmdline()
                cmdline_str = " ".join(parts) if parts else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Flagging logic
            is_flagged = name_lower in high_risk_names
            flag_reason: str | None = None
            if is_flagged:
                flag_reason = f"Process '{name}' is on the high-risk watchlist."

        return RawProcessSnapshot(
            timestamp=datetime.now(timezone.utc),
            pid=pid,
            process_name=name,
            cpu_percent=cpu,
            memory_mb=round(memory_mb, 3),
            disk_write_bytes=disk_write_bytes,
            exe_path=exe_path,
            parent_pid=parent_pid,
            parent_name=parent_name,
            cmdline=cmdline_str,
            is_flagged=is_flagged,
            flag_reason=flag_reason,
        )

    except psutil.NoSuchProcess:
        # Process terminated between enumeration and data collection — harmless
        return None
    except psutil.ZombieProcess:
        # Zombie processes have no meaningful telemetry
        return None
    except psutil.AccessDenied:
        # Kernel processes or protected processes — skip silently
        return None
    except Exception as exc:
        _log.debug(f"Unexpected error collecting process snapshot | pid={proc.pid} | {exc}")
        return None


# ===========================================================================
# Async DB Persistence
# ===========================================================================


async def _persist_process_snapshot(raw: RawProcessSnapshot) -> None:
    """
    Write a ``ProcessSnapshot`` ORM record to PostgreSQL.

    Args:
        raw: The raw snapshot DTO to persist.

    Raises:
        Exception: Propagated to caller for error counting.
    """
    record = ProcessSnapshot(
        timestamp=raw.timestamp,
        pid=raw.pid,
        process_name=raw.process_name,
        cpu_percent=raw.cpu_percent,
        memory_mb=raw.memory_mb,
        disk_write_bytes=raw.disk_write_bytes,
        exe_path=raw.exe_path,
        parent_pid=raw.parent_pid,
        parent_name=raw.parent_name,
        cmdline=raw.cmdline,
        is_flagged=raw.is_flagged,
        flag_reason=raw.flag_reason,
    )
    async with get_async_db_session() as session:
        session.add(record)


# ===========================================================================
# ProcessPoller — main controller
# ===========================================================================


class ProcessPoller:
    """
    Async lifecycle controller for the RDRS process telemetry poller.

    Runs an async loop that:
      1. Enumerates all running processes via psutil.
      2. Collects metrics in a thread-pool executor to avoid blocking the loop.
      3. Persists flagged and high-resource processes to PostgreSQL.
      4. Forwards all snapshots to an external queue for the scoring engine.

    Args:
        event_queue: External ``asyncio.Queue`` to forward ``RawProcessSnapshot``
                     objects to the scoring engine. Optional.
        poll_interval: Override for the poll interval (seconds). If None, reads
                       from ``settings.monitoring.process.poll_interval_seconds``.

    Example:
        poller = ProcessPoller(event_queue=engine.process_queue)
        await poller.start()
        await asyncio.sleep(30)
        await poller.stop()
    """

    def __init__(
        self,
        event_queue: asyncio.Queue[RawProcessSnapshot] | None = None,
        poll_interval: int | None = None,
    ) -> None:
        self._external_queue = event_queue
        self._poll_interval = (
            poll_interval or settings.monitoring.process.poll_interval_seconds
        )
        self._high_risk_names: frozenset[str] = frozenset(
            name.lower().removesuffix(".exe")
            for name in settings.monitoring.process.high_risk_processes
        )
        self._whitelist_names: frozenset[str] = frozenset(
            name.lower().removesuffix(".exe")
            for name in settings.monitoring.process.process_whitelist
        )
        self._stats = PollerStats()
        self._poll_task: asyncio.Task[None] | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start the process polling loop as a background asyncio task.

        Raises:
            RuntimeError: If the poller is already running.
        """
        if self._running:
            raise RuntimeError("ProcessPoller is already running.")

        # Prime psutil CPU percent accumulators non-blockingly.
        # First call always returns 0.0 — we call it once here so subsequent
        # per-process calls return real values after the first poll cycle.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._prime_cpu_counters)

        self._running = True
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="rdrs-process-poller"
        )
        _log.success(
            f"ProcessPoller started | "
            f"interval={self._poll_interval}s | "
            f"high_risk_watching={len(self._high_risk_names)} processes"
        )

    async def stop(self) -> None:
        """
        Gracefully stop the polling loop.

        Waits for the current cycle to complete before returning.
        """
        if not self._running:
            return

        _log.info("Stopping ProcessPoller...")
        self._running = False

        if self._poll_task is not None:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None

        _log.success(
            f"ProcessPoller stopped | "
            f"cycles={self._stats.poll_cycles} "
            f"snapshots={self._stats.total_snapshots} "
            f"persisted={self._stats.total_persisted} "
            f"flagged={self._stats.flagged_processes}"
        )

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        """
        Main async poll loop. Runs until cancelled by ``stop()``.

        Each cycle:
          1. Enumerates all running processes (in thread executor).
          2. Filters and persists notable snapshots.
          3. Sleeps for ``_poll_interval`` seconds.
        """
        _log.debug("Process poll loop started.")
        while self._running:
            try:
                await self._run_poll_cycle()
                self._stats.poll_cycles += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _log.exception(f"Unhandled error in process poll cycle: {exc}")

            try:
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break

    async def _run_poll_cycle(self) -> None:
        """
        Execute a single process collection cycle.

        Offloads the blocking ``psutil.process_iter()`` call to a thread executor,
        then persists and forwards snapshots asynchronously.
        """
        loop = asyncio.get_running_loop()

        # Collect all snapshots in a thread (psutil is synchronous)
        snapshots: list[RawProcessSnapshot] = await loop.run_in_executor(
            None, self._collect_all_processes
        )

        self._stats.total_snapshots += len(snapshots)

        # Log flagged processes with elevated priority
        for snap in snapshots:
            if snap.is_flagged:
                self._stats.flagged_processes += 1
                _log.bind(alert=True, event_type="HIGH_RISK_PROCESS").warning(
                    f"High-risk process detected | "
                    f"pid={snap.pid} | name={snap.process_name} | "
                    f"cpu={snap.cpu_percent:.1f}% | "
                    f"reason={snap.flag_reason}"
                )

        # Persist only flagged processes or high-resource processes to DB
        # (persisting ALL processes on every cycle would generate enormous volume)
        notable = self._filter_notable_snapshots(snapshots)
        persist_tasks = [
            asyncio.create_task(_persist_process_snapshot(s)) for s in notable
        ]
        if persist_tasks:
            results = await asyncio.gather(*persist_tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    _log.error(
                        f"Failed to persist ProcessSnapshot "
                        f"| pid={notable[i].pid} | error={result}"
                    )
                    self._stats.total_errors += 1
                else:
                    self._stats.total_persisted += 1

        # Forward ALL snapshots to scoring engine queue
        if self._external_queue is not None:
            for snap in snapshots:
                try:
                    self._external_queue.put_nowait(snap)
                except asyncio.QueueFull:
                    _log.warning(
                        "Scoring engine process queue full — "
                        f"dropping snapshot for pid={snap.pid}."
                    )

        _log.debug(
            f"Poll cycle complete | "
            f"total={len(snapshots)} | notable={len(notable)}"
        )

    def _collect_all_processes(self) -> list[RawProcessSnapshot]:
        """
        Synchronous helper (runs in thread executor) that enumerates all
        running processes and collects their snapshots.

        Returns:
            list[RawProcessSnapshot]: All successfully collected snapshots.
        """
        snapshots: list[RawProcessSnapshot] = []

        for proc in psutil.process_iter(
            attrs=["pid", "name", "status"],
            ad_value=None,
        ):
            snap = _collect_process_snapshot(
                proc,
                high_risk_names=self._high_risk_names,
                whitelist_names=self._whitelist_names,
            )
            if snap is not None:
                snapshots.append(snap)

        return snapshots

    def _filter_notable_snapshots(
        self, snapshots: list[RawProcessSnapshot]
    ) -> list[RawProcessSnapshot]:
        """
        Filter snapshots to only those worth persisting to the database.

        Criteria for persistence:
          - Process is flagged as high-risk.
          - CPU > 50% (potential encryption workload).
          - Disk write bytes > 100 MB (mass write activity).
          - Memory > 500 MB (anomalous memory usage).

        Args:
            snapshots: All snapshots from the current poll cycle.

        Returns:
            list[RawProcessSnapshot]: Subset worth writing to PostgreSQL.
        """
        notable: list[RawProcessSnapshot] = []
        for snap in snapshots:
            if (
                snap.is_flagged
                or snap.cpu_percent > 50.0
                or snap.disk_write_bytes > 100 * 1024 * 1024  # 100 MB
                or snap.memory_mb > 500.0
            ):
                notable.append(snap)
        return notable

    @staticmethod
    def _prime_cpu_counters() -> None:
        """
        Call ``cpu_percent(interval=None)`` on all processes once to initialize
        the internal psutil CPU accumulators.

        The first call always returns 0.0 per psutil documentation. Calling this
        once at startup means the first real poll cycle yields meaningful values.
        """
        for proc in psutil.process_iter(attrs=["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Return True if the poller is currently active."""
        return self._running

    @property
    def stats(self) -> PollerStats:
        """Return the current polling statistics."""
        return self._stats
