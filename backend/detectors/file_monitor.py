"""
backend/detectors/file_monitor.py
==================================
Real-time filesystem observer for the RDRS detection engine.

This module implements a non-blocking, event-driven filesystem watcher using
the ``watchdog`` library. It feeds the RDRS detection pipeline by:

  1. Observing configured directories for create / modify / delete / move events.
  2. Filtering noise (temporary files, hidden files, system artifacts).
  3. Computing Shannon entropy on created and modified files.
  4. Persisting structured ``FileEvent`` records to PostgreSQL.
  5. Publishing raw events to an ``asyncio.Queue`` for the scoring engine.

Architecture:
  Watchdog runs its ``Observer`` thread in the background. Events are dispatched
  to ``RDRSEventHandler.on_*`` methods on that thread. Since these callbacks are
  synchronous, DB persistence is offloaded to a dedicated asyncio task via
  ``asyncio.Queue``, keeping the observer thread non-blocking.

                 ┌────────────────────────────────┐
                 │  watchdog.Observer (thread)     │
                 │  RDRSEventHandler.on_*()        │
                 └──────────────┬─────────────────┘
                                │ put_nowait(raw_event)
                                ▼
                 ┌────────────────────────────────┐
                 │  asyncio.Queue[RawFileEvent]   │
                 └──────────────┬─────────────────┘
                                │ get()
                                ▼
                 ┌────────────────────────────────┐
                 │  _event_consumer task (async)  │
                 │  → entropy calc                │
                 │  → DB persist (FileEvent row)  │
                 │  → engine.ingest_file_event()  │
                 └────────────────────────────────┘

Usage:
    from backend.detectors.file_monitor import FileSystemMonitor

    monitor = FileSystemMonitor(event_queue=scoring_engine.file_queue)
    await monitor.start()
    ...
    await monitor.stop()
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers.polling import PollingObserver

from backend.core.config import settings
from backend.core.entropy import calculate_shannon_entropy
from backend.core.logging import audit_log, get_logger
from backend.database.models import FileEvent, FileEventType
from backend.database.session import get_async_db_session
from backend.api.routes.stream import publish_file_event

if TYPE_CHECKING:
    pass

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File name patterns that are always ignored (temporary / OS artifacts).
_IGNORED_PATTERNS: tuple[str, ...] = (
    "*.tmp",
    "*.temp",
    "~*",
    ".DS_Store",
    "desktop.ini",
    "Thumbs.db",
    "*.swp",
    "*.swo",
    "*.part",
    ".~lock.*",
    "__pycache__",
    "*.pyc",
    "*.pyo",
)

#: Maximum number of raw events buffered before the consumer catches up.
_QUEUE_MAX_SIZE: int = 4096

#: Max seconds to compute entropy before giving up (safety guard on large files).
_ENTROPY_TIMEOUT_SECONDS: float = 2.0


# ===========================================================================
# Data Transfer Objects
# ===========================================================================


@dataclass(slots=True)
class RawFileEvent:
    """
    Lightweight DTO carrying raw event data from the watchdog callback thread
    into the async consumer task. Intentionally free of heavy dependencies.

    Attributes:
        event_type:   Normalized event type string matching ``FileEventType``.
        src_path:     Absolute source file path.
        dst_path:     Absolute destination path (move events only).
        timestamp:    UTC datetime of event capture.
        is_directory: True if the event target is a directory (usually filtered).
    """

    event_type: str
    src_path: str
    dst_path: str | None
    timestamp: datetime
    is_directory: bool = False
    entropy_score: float | None = None



@dataclass
class FileEventStats:
    """
    Running statistics maintained by ``FileSystemMonitor`` for health reporting.

    Attributes:
        total_received:  Total events received from watchdog.
        total_filtered:  Events discarded by the noise filter.
        total_persisted: Events successfully written to the database.
        total_errors:    Events that failed during processing.
    """

    total_received: int = 0
    total_filtered: int = 0
    total_persisted: int = 0
    total_errors: int = 0
    events_per_type: dict[str, int] = field(default_factory=dict)

    def record(self, event_type: str) -> None:
        """Increment per-type counter."""
        self.events_per_type[event_type] = self.events_per_type.get(event_type, 0) + 1


# ===========================================================================
# Watchdog Event Handler
# ===========================================================================


class RDRSEventHandler(FileSystemEventHandler):
    """
    Custom ``watchdog`` event handler that dispatches filesystem events into
    the RDRS async processing pipeline.

    This class runs on the watchdog Observer thread. All methods must be
    fast and non-blocking — heavy work (entropy, DB) is pushed to the queue.

    Args:
        raw_queue:     Thread-safe queue shared with the async consumer.
        stats:         Mutable stats object for monitoring counters.
        loop:          The running asyncio event loop (for ``call_soon_threadsafe``).
    """

    def __init__(
        self,
        raw_queue: asyncio.Queue[RawFileEvent],
        stats: FileEventStats,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__()
        self._queue = raw_queue
        self._stats = stats
        self._loop = loop
        self._suspicious_exts: frozenset[str] = frozenset(
            settings.monitoring.filesystem.suspicious_extensions
        )
        self._ransom_note_patterns: list[str] = (
            settings.monitoring.filesystem.ransom_note_patterns
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_ignore(self, path: str) -> bool:
        """
        Determine whether a file path should be silently discarded.

        Ignores:
          - Directory events (handled separately if needed).
          - Hidden files (name starts with '.').
          - Files matching any pattern in ``_IGNORED_PATTERNS``.

        Args:
            path: Absolute file path string.

        Returns:
            bool: True if the event should be discarded.
        """
        name = os.path.basename(path)

        # Hidden files on Unix/macOS
        if name.startswith("."):
            return True

        # Windows hidden system files starting with '$'
        if name.startswith("$"):
            return True

        # Pattern-based ignore list
        for pattern in _IGNORED_PATTERNS:
            if fnmatch.fnmatch(name, pattern):
                return True

        return False

    def _is_ransom_note(self, path: str) -> bool:
        """Return True if the filename matches any known ransom note pattern."""
        name = os.path.basename(path)
        return any(fnmatch.fnmatch(name.upper(), p.upper()) for p in self._ransom_note_patterns)

    def _is_suspicious_extension(self, path: str) -> bool:
        """Return True if the file extension is on the suspicious extension list."""
        ext = Path(path).suffix.lower()
        return ext in self._suspicious_exts

    def _enqueue(self, event: RawFileEvent) -> None:
        """
        Thread-safely schedule the event onto the asyncio queue.

        Uses ``call_soon_threadsafe`` to wake up the event loop from the
        watchdog Observer thread without blocking it.

        Args:
            event: The raw event DTO to enqueue.
        """
        self._stats.total_received += 1
        self._stats.record(event.event_type)

        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
        except asyncio.QueueFull:
            _log.warning(
                "File event queue full — dropping event. "
                "Consider increasing _QUEUE_MAX_SIZE or reducing watch scope. "
                f"| path={event.src_path}"
            )
            self._stats.total_errors += 1

    # ------------------------------------------------------------------
    # watchdog event hooks
    # ------------------------------------------------------------------

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if event.is_directory or self._should_ignore(event.src_path):
            self._stats.total_filtered += 1
            return

        priority_flag = (
            self._is_ransom_note(event.src_path)
            or self._is_suspicious_extension(event.src_path)
        )
        if priority_flag:
            _log.bind(alert=True, event_type="FILE_CREATED").warning(
                f"HIGH-PRIORITY creation detected | path={event.src_path}"
            )

        self._enqueue(
            RawFileEvent(
                event_type=FileEventType.CREATED.value,
                src_path=event.src_path,
                dst_path=None,
                timestamp=datetime.now(timezone.utc),
            )
        )

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if event.is_directory or self._should_ignore(event.src_path):
            self._stats.total_filtered += 1
            return

        self._enqueue(
            RawFileEvent(
                event_type=FileEventType.MODIFIED.value,
                src_path=event.src_path,
                dst_path=None,
                timestamp=datetime.now(timezone.utc),
            )
        )

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion events."""
        if event.is_directory or self._should_ignore(event.src_path):
            self._stats.total_filtered += 1
            return

        self._enqueue(
            RawFileEvent(
                event_type=FileEventType.DELETED.value,
                src_path=event.src_path,
                dst_path=None,
                timestamp=datetime.now(timezone.utc),
            )
        )

    def on_moved(self, event: FileSystemEvent) -> None:
        """
        Handle file rename / move events.

        Moves are treated as renames in the RDRS threat model. The destination
        extension is the relevant signal (e.g., ``.docx`` → ``.locked``).
        """
        if event.is_directory or self._should_ignore(event.src_path):
            self._stats.total_filtered += 1
            return

        dst: str = getattr(event, "dest_path", event.src_path)
        if self._is_suspicious_extension(dst):
            _log.bind(alert=True, event_type="FILE_RENAME").warning(
                f"Suspicious rename to known ransomware extension "
                f"| src={event.src_path} | dst={dst}"
            )

        self._enqueue(
            RawFileEvent(
                event_type=FileEventType.RENAMED.value,
                src_path=event.src_path,
                dst_path=dst,
                timestamp=datetime.now(timezone.utc),
            )
        )


# ===========================================================================
# Async Consumer
# ===========================================================================


async def _compute_entropy_safe(path: str) -> float | None:
    """
    Run the entropy calculator in a thread-pool executor to keep the event
    loop non-blocking during file I/O.

    Returns ``None`` if entropy calculation exceeds ``_ENTROPY_TIMEOUT_SECONDS``
    or fails for any reason.

    Args:
        path: Absolute path to the file to analyze.

    Returns:
        float | None: Entropy value in [0.0, 8.0], or None on failure/timeout.
    """
    loop = asyncio.get_running_loop()
    try:
        entropy = await asyncio.wait_for(
            loop.run_in_executor(
                None,  # default ThreadPoolExecutor
                calculate_shannon_entropy,
                path,
            ),
            timeout=_ENTROPY_TIMEOUT_SECONDS,
        )
        return entropy
    except asyncio.TimeoutError:
        _log.warning(f"Entropy calculation timed out after {_ENTROPY_TIMEOUT_SECONDS}s | path={path}")
        return None
    except Exception as exc:
        _log.error(f"Entropy calculation failed | path={path} | error={exc}")
        return None


async def _persist_file_event(
    raw: RawFileEvent,
    entropy_score: float | None,
) -> dict:
    """
    Persist a ``FileEvent`` ORM record to PostgreSQL.

    Args:
        raw:           The raw event DTO from the watchdog queue.
        entropy_score: Pre-computed entropy value; may be None.
    """
    path = Path(raw.src_path)
    file_size: int | None = None

    try:
        if path.exists() and path.is_file():
            file_size = path.stat().st_size
    except OSError:
        pass

    record = FileEvent(
        timestamp=raw.timestamp,
        event_type=raw.event_type,
        file_path=raw.src_path,
        destination_path=raw.dst_path,
        file_extension=Path(raw.dst_path or raw.src_path).suffix.lower() or None,
        entropy_score=entropy_score,
        file_size_bytes=file_size,
    )

    async with get_async_db_session() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)

    _log.bind(event_type=raw.event_type).debug(
        f"FileEvent persisted | type={raw.event_type} "
        f"| path={path.name} | entropy={entropy_score}"
    )
    
    # Return dictionary for SSE
    return {
        "id": str(record.id),
        "timestamp": record.timestamp.isoformat(),
        "event_type": record.event_type,
        "file_path": record.file_path,
        "destination_path": record.destination_path,
        "file_extension": record.file_extension,
        "entropy_score": record.entropy_score,
        "file_size_bytes": record.file_size_bytes,
    }


# ===========================================================================
# FileSystemMonitor — main controller
# ===========================================================================


class FileSystemMonitor:
    """
    Lifecycle controller for the RDRS real-time filesystem observer.

    Manages the watchdog ``Observer`` thread and the async consumer task
    that processes events from the internal queue.

    Args:
        event_queue: External ``asyncio.Queue`` where processed ``RawFileEvent``
                     objects are forwarded for consumption by the scoring engine.
                     If None, events are persisted to DB only.
        loop:        The running event loop. Defaults to the current loop.

    Example:
        monitor = FileSystemMonitor(event_queue=engine.file_queue)
        await monitor.start()
        # ... application runs ...
        await monitor.stop()
    """

    def __init__(
        self,
        event_queue: asyncio.Queue[RawFileEvent] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._external_queue = event_queue
        self._loop: asyncio.AbstractEventLoop = loop or asyncio.get_event_loop()
        self._internal_queue: asyncio.Queue[RawFileEvent] = asyncio.Queue(
            maxsize=_QUEUE_MAX_SIZE
        )
        self._stats = FileEventStats()
        self._observer: PollingObserver | None = None
        self._consumer_task: asyncio.Task[None] | None = None
        self._stop_event = threading.Event()
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start the filesystem observer and async consumer task.

        Validates all configured watch paths before starting. Logs a warning
        for any paths that do not exist (monitoring is skipped for those).

        Raises:
            RuntimeError: If the monitor is already running.
        """
        if self._running:
            raise RuntimeError("FileSystemMonitor is already running.")

        watch_paths = settings.get_watch_paths()
        recursive = settings.monitoring.filesystem.recursive

        handler = RDRSEventHandler(
            raw_queue=self._internal_queue,
            stats=self._stats,
            loop=self._loop,
        )

        self._observer = PollingObserver(timeout=1.0)
        scheduled_count = 0

        for path in watch_paths:
            if not path.exists():
                _log.warning(
                    f"Watch path does not exist — skipping | path={path}. "
                    f"Create the directory or update config.yaml."
                )
                continue
            self._observer.schedule(handler, str(path), recursive=recursive)
            scheduled_count += 1
            _log.info(f"Scheduled watch | path={path} | recursive={recursive}")

        if scheduled_count == 0:
            _log.error(
                "No valid watch paths could be scheduled. "
                "FileSystemMonitor will not observe any directories."
            )

        # Start watchdog Observer thread
        self._observer.start()

        # Start async consumer task
        self._consumer_task = asyncio.create_task(
            self._event_consumer(), name="rdrs-fs-consumer"
        )

        self._running = True
        _log.success(
            f"FileSystemMonitor started | "
            f"watching {scheduled_count}/{len(watch_paths)} paths"
        )

    async def stop(self) -> None:
        """
        Gracefully stop the observer thread and consumer task.

        Waits for the consumer to drain any remaining queued events before
        completing shutdown (up to 5 seconds).
        """
        if not self._running:
            return

        _log.info("Stopping FileSystemMonitor...")
        self._running = False

        # Stop watchdog thread
        if self._observer is not None:
            self._observer.stop()
            await asyncio.get_event_loop().run_in_executor(None, self._observer.join)
            self._observer = None

        # Drain and cancel consumer
        if self._consumer_task is not None:
            try:
                await asyncio.wait_for(self._drain_queue(), timeout=5.0)
            except asyncio.TimeoutError:
                _log.warning("Queue drain timed out during shutdown.")
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None

        _log.success(
            f"FileSystemMonitor stopped | "
            f"stats: received={self._stats.total_received} "
            f"filtered={self._stats.total_filtered} "
            f"persisted={self._stats.total_persisted} "
            f"errors={self._stats.total_errors}"
        )

    async def _drain_queue(self) -> None:
        """Process all remaining events in the internal queue before shutdown."""
        while not self._internal_queue.empty():
            try:
                raw = self._internal_queue.get_nowait()
                await self._process_event(raw)
                self._internal_queue.task_done()
            except asyncio.QueueEmpty:
                break

    # ------------------------------------------------------------------
    # Consumer loop
    # ------------------------------------------------------------------

    async def _event_consumer(self) -> None:
        """
        Async task that continuously drains the internal event queue.

        For each event:
          1. Compute entropy (for create/modify events).
          2. Persist to PostgreSQL.
          3. Forward to the external scoring engine queue (if configured).

        Runs until cancelled during ``stop()``.
        """
        _log.debug("File event consumer task started.")
        while True:
            try:
                raw: RawFileEvent = await self._internal_queue.get()
                await self._process_event(raw)
                self._internal_queue.task_done()
            except asyncio.CancelledError:
                _log.debug("File event consumer task cancelled.")
                break
            except Exception as exc:
                _log.exception(f"Unhandled error in file event consumer: {exc}")
                self._stats.total_errors += 1

    async def _process_event(self, raw: RawFileEvent) -> None:
        """
        Process a single raw file event end-to-end.

        Args:
            raw: The raw event from the internal queue.
        """
        entropy: float | None = None

        # Compute entropy for create/modify events on existing files
        if raw.event_type in (FileEventType.CREATED.value, FileEventType.MODIFIED.value):
            entropy = await _compute_entropy_safe(raw.src_path)

        # Persist to database
        try:
            event_dict = await _persist_file_event(raw, entropy)
            self._stats.total_persisted += 1
            await publish_file_event(event_dict)
        except Exception as exc:
            _log.error(
                f"Failed to persist FileEvent | "
                f"path={raw.src_path} | error={exc}"
            )
            self._stats.total_errors += 1
            return

        # Forward to external queue (scoring engine)
        if self._external_queue is not None:
            try:
                self._external_queue.put_nowait(raw)
            except asyncio.QueueFull:
                _log.warning("Scoring engine queue full — event not forwarded.")

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Return True if the monitor is currently active."""
        return self._running

    @property
    def stats(self) -> FileEventStats:
        """Return the current event processing statistics."""
        return self._stats

    def get_queue_depth(self) -> int:
        """Return the number of events currently buffered in the internal queue."""
        return self._internal_queue.qsize()
