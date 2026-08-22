"""
backend/detectors/engine.py
============================
Sliding-window threat scoring and rule evaluation engine for RDRS.

This is the analytical core of the detection pipeline. It consumes raw events
from the filesystem monitor and process poller, evaluates them against a set of
behavioral detection rules, and produces a continuous Threat Score (0.0–100.0).

Architecture Overview:
    ┌─────────────────────────────────────────────────────────────┐
    │                   ThreatScoringEngine                       │
    │                                                             │
    │  ┌────────────┐   ┌──────────────┐   ┌───────────────────┐ │
    │  │ File Event │   │ Process      │   │ Score History     │ │
    │  │ Window     │   │ Window       │   │ (deque, maxlen=N) │ │
    │  │ (60s deque)│   │ (60s deque)  │   └───────────────────┘ │
    │  └──────┬─────┘   └──────┬───────┘                         │
    │         │                │                                  │
    │  ┌──────▼────────────────▼──────────────────────────────┐  │
    │  │                 Rule Evaluators                       │  │
    │  │  ① FileModificationVelocity   weight=0.30            │  │
    │  │  ② MassRenameDetector         weight=0.30 (shared)   │  │
    │  │  ③ HighEntropyDetector        weight=0.25            │  │
    │  │  ④ ProcessResourceSpike       weight=0.20            │  │
    │  │  ⑤ ShadowCopyDetector         weight=0.15            │  │
    │  └──────────────────────────┬────────────────────────────┘  │
    │                             │                                │
    │  ┌──────────────────────────▼────────────────────────────┐  │
    │  │   Composite Score = Σ(weight_i × signal_i) × 100      │  │
    │  │   Decay applied per event: e^(-λ × Δt)                │  │
    │  └──────────────────────────┬────────────────────────────┘  │
    │                             │                                │
    │  ┌──────────────────────────▼────────────────────────────┐  │
    │  │  Persist ThreatScore row → Trigger IncidentResponder    │  │
    │  └────────────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────┘

Scoring Model:
    ThreatScore(t) = clamp(Σ [ w_i × s_i(t) × e^(-λ × Δt_i) ] × 100, 0, 100)

    Where:
      w_i  = detector weight from config (sum == 1.0)
      s_i  = normalized signal value ∈ [0.0, 1.0]
      Δt_i = age of the signal in seconds
      λ    = decay lambda from config (default: 0.05)

Severity Bands (per task specification):
    Normal   :  0.0 – 40.0
    Warning  : 40.0 – 70.0
    Critical : 70.0 – 100.0

Usage:
    from backend.detectors.engine import ThreatScoringEngine

    engine = ThreatScoringEngine()
    await engine.start()

    # Feed events from monitors:
    await engine.ingest_file_event(raw_file_event)
    await engine.ingest_process_snapshot(raw_process_snapshot)
"""

from __future__ import annotations

import asyncio
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from loguru import logger

from backend.core.config import settings
from backend.core.logging import audit_log, get_logger
from backend.database.models import SeverityLevel, ThreatScore, Incident
from backend.database.session import get_async_db_session
from backend.detectors.file_monitor import RawFileEvent
from backend.detectors.process_poller import RawProcessSnapshot
from backend.detectors.responder import IncidentResponder

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity band mapping (per task spec — different from ARCHITECTURE.md bands)
# ---------------------------------------------------------------------------
_SEVERITY_BANDS: list[tuple[float, float, str]] = [
    (0.0, 40.0, SeverityLevel.NOMINAL.value),    # Normal
    (40.0, 70.0, SeverityLevel.MEDIUM.value),    # Warning
    (70.0, 100.0, SeverityLevel.CRITICAL.value), # Critical
]


def _classify_score(score: float) -> str:
    """
    Map a raw threat score to its severity level string.

    Bands (per Phase 3 specification):
      - Normal   :  0.0 – 40.0  → NOMINAL
      - Warning  : 40.0 – 70.0  → MEDIUM
      - Critical : 70.0 – 100.0 → CRITICAL

    Args:
        score: Threat score in [0.0, 100.0].

    Returns:
        str: One of "NOMINAL", "MEDIUM", "CRITICAL".
    """
    for low, high, label in _SEVERITY_BANDS:
        if low <= score < high:
            return label
    return SeverityLevel.CRITICAL.value  # score == 100.0


# ===========================================================================
# Signal DTOs
# ===========================================================================


@dataclass(slots=True)
class Signal:
    """
    A scored output from a single detection rule.

    Attributes:
        rule_name:  Identifier matching config ``detector_weights`` keys.
        value:      Normalized signal strength ∈ [0.0, 1.0].
        timestamp:  UTC time when the signal was produced.
        evidence:   Free-text description of the triggering condition.
    """

    rule_name: str
    value: float
    timestamp: datetime
    evidence: str


@dataclass
class ScoringResult:
    """
    Full output of one scoring cycle.

    Attributes:
        score:             Composite threat score (0.0–100.0).
        severity:          Severity band label.
        signals:           Per-detector signals that contributed.
        signal_breakdown:  Dict of rule_name → signal value for DB storage.
        triggered_rules:   Names of rules with value > 0.
        timestamp:         UTC time of this calculation.
    """

    score: float
    severity: str
    signals: list[Signal]
    signal_breakdown: dict[str, float]
    triggered_rules: list[str]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ===========================================================================
# Sliding Window
# ===========================================================================


class SlidingWindow:
    """
    A time-bounded sliding window of events backed by a ``deque``.

    Events older than ``window_seconds`` are automatically evicted whenever
    ``append()`` or ``purge_expired()`` is called.

    Args:
        window_seconds: Duration of the sliding window in seconds.
    """

    def __init__(self, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._items: deque[tuple[datetime, object]] = deque()

    def append(self, timestamp: datetime, item: object) -> None:
        """Append an item and evict expired entries."""
        self._items.append((timestamp, item))
        self.purge_expired()

    def purge_expired(self) -> None:
        """Remove all entries older than ``window_seconds``."""
        now = datetime.now(timezone.utc)
        cutoff_seconds = self._window_seconds
        self._items = deque(
            (ts, item) for ts, item in self._items
            if (now - ts).total_seconds() <= cutoff_seconds
        )


    def get_items(self) -> list[tuple[datetime, object]]:
        """Return all currently valid (non-expired) items."""
        self.purge_expired()
        return list(self._items)

    def __len__(self) -> int:
        self.purge_expired()
        return len(self._items)


# ===========================================================================
# Detection Rule Evaluators
# ===========================================================================


class _RuleEvaluator:
    """
    Abstract base for all detection rule evaluators.

    Each subclass implements ``evaluate()`` which reads from the shared
    sliding windows and returns a normalized Signal (or None if no signal).
    """

    rule_name: str = "base"

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        """
        Evaluate the detection rule against current window data.

        Args:
            file_window:    Sliding window of ``RawFileEvent`` objects.
            process_window: Sliding window of ``RawProcessSnapshot`` objects.

        Returns:
            Signal | None: A signal if the rule fires; None otherwise.
        """
        raise NotImplementedError


class FileModificationVelocityRule(_RuleEvaluator):
    """
    Rule ①: Detect high-frequency file modification / creation events.

    Signal is proportional to the modification rate within the window,
    normalized against the configured max rate.

    Fires when:
        modifications_per_minute > trigger_rate × 60
    """

    rule_name = "file_rename"

    def __init__(self) -> None:
        cfg = settings.threat_scoring.file_rename
        self._trigger_rate = cfg.trigger_rate_per_second * 60  # ops/min
        self._max_rate = cfg.max_rate_per_second * 60

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        events = file_window.get_items()
        modify_count = sum(
            1 for _, e in events
            if isinstance(e, RawFileEvent)
            and e.event_type in ("modified", "created", "renamed")
        )

        window_minutes = settings.threat_scoring.window_seconds / 60.0
        rate_per_min = modify_count / max(window_minutes, 0.0001)

        if rate_per_min < self._trigger_rate:
            return None

        signal_value = min(
            (rate_per_min - self._trigger_rate) / max(self._max_rate - self._trigger_rate, 1.0),
            1.0,
        )

        return Signal(
            rule_name=self.rule_name,
            value=signal_value,
            timestamp=datetime.now(timezone.utc),
            evidence=(
                f"File modification velocity: {rate_per_min:.1f} ops/min "
                f"(trigger={self._trigger_rate:.0f}, max={self._max_rate:.0f})"
            ),
        )


class MassRenameDetectorRule(_RuleEvaluator):
    """
    Rule ②: Detect mass file renames to suspicious extensions.

    Fires immediately when any rename-to-suspicious-extension is detected,
    with signal proportional to the count of such renames in the window.
    """

    rule_name = "mass_rename"  # Separated from file_rename to apply flat penalty

    def __init__(self) -> None:
        self._suspicious_exts: frozenset[str] = frozenset(
            settings.monitoring.filesystem.suspicious_extensions
        )

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        events = file_window.get_items()
        suspicious_renames = [
            e for _, e in events
            if isinstance(e, RawFileEvent)
            and e.event_type == "renamed"
            and e.dst_path is not None
            and any(e.dst_path.lower().endswith(ext) for ext in self._suspicious_exts)
        ]

        if not suspicious_renames:
            return None

        count = len(suspicious_renames)
        # Signal grows quickly: 1 event → 0.5, 5+ events → ~1.0
        signal_value = min(count / 5.0, 1.0)

        sample_paths = [e.dst_path for e in suspicious_renames[:3]]  # type: ignore[union-attr]
        return Signal(
            rule_name=self.rule_name,
            value=signal_value,
            timestamp=datetime.now(timezone.utc),
            evidence=(
                f"{count} suspicious extension renames detected | "
                f"sample_paths={sample_paths}"
            ),
        )


class HighEntropyDetectorRule(_RuleEvaluator):
    """
    Rule ③: Detect files with anomalously high Shannon entropy.

    Fires when created/modified files in the window have entropy scores
    above the configured threshold (default: 7.0 bits/byte), indicating
    likely encryption.
    """

    rule_name = "entropy"

    def __init__(self) -> None:
        cfg = settings.threat_scoring.entropy
        self._min_delta = cfg.min_entropy_delta
        self._high_threshold = 7.0  # bits/byte — likely encrypted

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        events = file_window.get_items()

        # Collect entropy scores from create/modify events
        entropy_scores: list[float] = [
            e.entropy_score  # type: ignore[union-attr]
            for _, e in events
            if isinstance(e, RawFileEvent)
            and e.event_type in ("created", "modified")
            and hasattr(e, "entropy_score")
            and getattr(e, "entropy_score", None) is not None
            and e.entropy_score >= self._high_threshold  # type: ignore[operator]
        ]

        if not entropy_scores:
            return None

        count = len(entropy_scores)
        avg_entropy = sum(entropy_scores) / count
        # Signal: avg entropy normalized from threshold to 8.0
        signal_value = min(
            (avg_entropy - self._high_threshold) / (8.0 - self._high_threshold),
            1.0,
        )
        signal_value = max(signal_value, 0.1 * min(count / 3.0, 1.0))

        return Signal(
            rule_name=self.rule_name,
            value=min(signal_value, 1.0),
            timestamp=datetime.now(timezone.utc),
            evidence=(
                f"{count} high-entropy files detected | "
                f"avg_entropy={avg_entropy:.3f} | threshold={self._high_threshold}"
            ),
        )


class ProcessResourceSpikeRule(_RuleEvaluator):
    """
    Rule ④: Detect processes with anomalous CPU + disk write activity.

    Ransomware typically exhibits a combined pattern of:
      - High CPU (encryption computation)
      - High disk write throughput (writing encrypted output)

    Fires when any non-whitelisted process in the window exceeds thresholds.
    """

    rule_name = "process_chain"

    _CPU_SPIKE_THRESHOLD: float = 70.0      # %
    _DISK_WRITE_THRESHOLD: int = 50_000_000  # 50 MB

    def __init__(self) -> None:
        self._whitelist: frozenset[str] = frozenset(
            name.lower().removesuffix(".exe")
            for name in settings.monitoring.process.process_whitelist
        )

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        snapshots = process_window.get_items()
        anomalous: list[RawProcessSnapshot] = []

        for _, snap in snapshots:
            if not isinstance(snap, RawProcessSnapshot):
                continue
            name_lower = snap.process_name.lower().removesuffix(".exe")
            if name_lower in self._whitelist:
                continue
            if (
                snap.cpu_percent >= self._CPU_SPIKE_THRESHOLD
                or snap.disk_write_bytes >= self._DISK_WRITE_THRESHOLD
            ):
                anomalous.append(snap)

        if not anomalous:
            return None

        # Score by the maximum CPU spike observed
        max_cpu = max(s.cpu_percent for s in anomalous)
        signal_value = min(
            (max_cpu - self._CPU_SPIKE_THRESHOLD) / (100.0 - self._CPU_SPIKE_THRESHOLD),
            1.0,
        )
        signal_value = max(signal_value, 0.2)  # Minimum signal for any match

        suspect_names = list({s.process_name for s in anomalous})[:5]
        return Signal(
            rule_name=self.rule_name,
            value=signal_value,
            timestamp=datetime.now(timezone.utc),
            evidence=(
                f"{len(anomalous)} anomalous processes detected | "
                f"max_cpu={max_cpu:.1f}% | suspects={suspect_names}"
            ),
        )


class ShadowCopyDetectorRule(_RuleEvaluator):
    """
    Rule ⑤: Detect shadow copy deletion / backup disruption attempts.

    Fires when any process in the window matches a high-risk process name
    associated with shadow copy manipulation (vssadmin, wbadmin, bcdedit, wmic).
    """

    rule_name = "shadow_copy"

    _SHADOW_COPY_PROCESSES: frozenset[str] = frozenset(
        {"vssadmin", "wbadmin", "bcdedit", "wmic"}
    )

    def evaluate(
        self,
        file_window: SlidingWindow,
        process_window: SlidingWindow,
    ) -> Signal | None:
        snapshots = process_window.get_items()
        matches: list[RawProcessSnapshot] = []

        for _, snap in snapshots:
            if not isinstance(snap, RawProcessSnapshot):
                continue
            name_lower = snap.process_name.lower().removesuffix(".exe")
            if name_lower in self._SHADOW_COPY_PROCESSES:
                matches.append(snap)

        if not matches:
            return None

        # Any shadow copy process is a high-confidence signal
        signal_value = min(0.4 + (len(matches) - 1) * 0.2, 1.0)
        names = [s.process_name for s in matches[:3]]

        return Signal(
            rule_name=self.rule_name,
            value=signal_value,
            timestamp=datetime.now(timezone.utc),
            evidence=(
                f"Shadow copy disruption processes detected | "
                f"processes={names} | count={len(matches)}"
            ),
        )


# ===========================================================================
# Threat Scoring Engine
# ===========================================================================


class ThreatScoringEngine:
    """
    Real-time sliding-window threat scoring and rule evaluation engine.

    Ingests filesystem events and process snapshots, evaluates behavioral
    detection rules, and produces periodic threat score calculations stored
    in PostgreSQL.

    Args:
        response_callback: Optional async callable invoked with a ``ScoringResult``
                           whenever the score crosses the CRITICAL threshold (70+).
                           Used to trigger the response handler.
        score_interval:    Seconds between scoring cycles. Defaults to 5s.

    Queues (for direct event ingestion from monitors):
        file_queue:    asyncio.Queue[RawFileEvent]
        process_queue: asyncio.Queue[RawProcessSnapshot]

    Example:
        engine = ThreatScoringEngine(response_callback=handler.on_critical)
        await engine.start()

        # Monitors push to the engine's queues directly:
        monitor = FileSystemMonitor(event_queue=engine.file_queue)
        poller  = ProcessPoller(event_queue=engine.process_queue)
    """

    def __init__(
        self,
        response_callback: Callable[[ScoringResult], None] | None = None,
        score_interval: float = 5.0,
    ) -> None:
        cfg = settings.threat_scoring
        self._window_seconds = cfg.window_seconds
        self._decay_lambda = cfg.decay_lambda
        self._weights = cfg.detector_weights

        self._file_window = SlidingWindow(self._window_seconds)
        self._process_window = SlidingWindow(self._window_seconds)

        # Public ingest queues (monitors write here)
        self.file_queue: asyncio.Queue[RawFileEvent] = asyncio.Queue(maxsize=4096)
        self.process_queue: asyncio.Queue[RawProcessSnapshot] = asyncio.Queue(maxsize=2048)

        self._response_callback = response_callback
        self._score_interval = score_interval

        # Rule evaluators
        self._velocity_rule = FileModificationVelocityRule()
        self._rename_rule = MassRenameDetectorRule()
        self._entropy_rule = HighEntropyDetectorRule()
        self._process_rule = ProcessResourceSpikeRule()
        self._shadow_rule = ShadowCopyDetectorRule()

        # State
        self._current_score: float = 0.0
        self._current_severity: str = SeverityLevel.NOMINAL.value
        self._score_history: deque[ScoringResult] = deque(maxlen=720)  # 1h at 5s intervals
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []
        self._last_alert_time: datetime | None = None
        self._last_heartbeat_time: datetime | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the ingest consumers and scoring loop tasks."""
        if self._running:
            raise RuntimeError("ThreatScoringEngine is already running.")

        self._running = True
        self._tasks = [
            asyncio.create_task(self._file_event_consumer(), name="engine-file-consumer"),
            asyncio.create_task(self._process_consumer(), name="engine-proc-consumer"),
            asyncio.create_task(self._scoring_loop(), name="engine-scoring-loop"),
        ]
        _log.success(
            f"ThreatScoringEngine started | "
            f"window={self._window_seconds}s | "
            f"decay_λ={self._decay_lambda} | "
            f"score_interval={self._score_interval}s"
        )

    async def stop(self) -> None:
        """Gracefully stop all engine tasks."""
        if not self._running:
            return

        _log.info("Stopping ThreatScoringEngine...")
        self._running = False

        for task in self._tasks:
            task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        _log.success("ThreatScoringEngine stopped.")

    # ------------------------------------------------------------------
    # Event ingest consumers
    # ------------------------------------------------------------------

    async def _file_event_consumer(self) -> None:
        """Drain file_queue and add events to the sliding window."""
        while self._running:
            try:
                event: RawFileEvent = await self.file_queue.get()
                self._file_window.append(event.timestamp, event)
                self.file_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.error(f"File event consumer error: {exc}")

    async def _process_consumer(self) -> None:
        """Drain process_queue and add snapshots to the sliding window."""
        while self._running:
            try:
                snap: RawProcessSnapshot = await self.process_queue.get()
                self._process_window.append(snap.timestamp, snap)
                self.process_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.error(f"Process consumer error: {exc}")

    # ------------------------------------------------------------------
    # Scoring loop
    # ------------------------------------------------------------------

    async def _scoring_loop(self) -> None:
        """
        Run one scoring cycle every ``_score_interval`` seconds.

        Each cycle:
          1. Evaluates all detection rules against current windows.
          2. Computes the composite weighted score with exponential decay.
          3. Persists the ThreatScore record to PostgreSQL.
          4. Triggers the response callback if score is CRITICAL.
        """
        _log.debug("Scoring loop started.")
        while self._running:
            try:
                await asyncio.sleep(self._score_interval)
                result = self._evaluate()
                self._current_score = result.score
                self._current_severity = result.severity
                self._score_history.append(result)

                await self._persist_score(result)

                now = datetime.now(timezone.utc)
                if result.score >= 70.0:
                    if getattr(self, "_last_incident_time", None) is None or (now - self._last_incident_time).total_seconds() > 60:
                        self._last_incident_time = now
                        import uuid
                        import re
                        
                        incident_id = str(uuid.uuid4())
                    
                    # 1. Mint Incident
                    incident = Incident(
                        id=uuid.UUID(incident_id),
                        timestamp=result.timestamp,
                        threat_score=result.score,
                        severity_level=result.severity,
                        response_mode="simulation",
                        resolved=False,
                    )
                    
                    try:
                        async with get_async_db_session() as session:
                            session.add(incident)
                            await session.flush()
                            await session.refresh(incident)
                    except Exception as e:
                        _log.error(f"Failed to persist Incident: {e}")

                    # 2. Extract context
                    affected_files = []
                    for sig in result.signals:
                        if sig.rule_name in ("file_rename", "entropy"):
                            paths = re.findall(r"[A-Za-z]:[/\\][\w\\/.\-]+|/[\w/.\-]+", sig.evidence)
                            affected_files.extend(paths)
                            
                    suspect_pid = "unknown"
                    for sig in result.signals:
                        if sig.rule_name == "process_chain":
                            pids = re.findall(r"pid[=:](\d+)", sig.evidence, re.IGNORECASE)
                            if pids:
                                suspect_pid = pids[0]
                                break

                    # 3. Trigger Phase 5 Playbook
                    responder = IncidentResponder()
                    if affected_files:
                        responder.quarantine_evidence(incident_id, affected_files)
                        
                    responder.simulate_neutralization(suspect_pid)
                    
                    # 4. Broadcast Playbook Alert to Frontend
                    await responder.broadcast_mitigation_alert(incident_id, suspect_pid)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.exception(f"Scoring loop error: {exc}")

    # ------------------------------------------------------------------
    # Scoring computation
    # ------------------------------------------------------------------

    def _evaluate(self) -> ScoringResult:
        """
        Run all detection rules and compute the composite threat score.

        Applies exponential decay based on signal age within the window.
        Returns a complete ScoringResult.

        Returns:
            ScoringResult: Full scoring result for this cycle.
        """
        now = datetime.now(timezone.utc)
        signals: list[Signal] = []

        # Evaluate each rule — take the maximum signal per rule_name
        # (velocity and mass-rename share "file_rename" weight)
        rule_signals: dict[str, Signal] = {}
        for evaluator in [
            self._velocity_rule,
            self._rename_rule,
            self._entropy_rule,
            self._process_rule,
            self._shadow_rule,
        ]:
            sig = evaluator.evaluate(self._file_window, self._process_window)
            if sig is None:
                continue
            existing = rule_signals.get(sig.rule_name)
            if existing is None or sig.value > existing.value:
                rule_signals[sig.rule_name] = sig

        signals = list(rule_signals.values())

        # Compute weighted sum with exponential decay per signal age
        weights_map: dict[str, float] = {
            "file_rename":    self._weights.file_rename,
            "entropy":        self._weights.entropy,
            "process_chain":  self._weights.process_chain,
            "shadow_copy":    self._weights.shadow_copy,
            "network_beacon": self._weights.network_beacon,
            "mass_rename":    0.0,  # Uses flat penalty instead of percentage weight
        }

        weighted_sum = 0.0
        signal_breakdown: dict[str, float] = {}

        for sig in signals:
            age_seconds = (now - sig.timestamp).total_seconds()
            decay = math.exp(-self._decay_lambda * max(age_seconds, 0.0))
            weight = weights_map.get(sig.rule_name, 0.0)
            contribution = weight * sig.value * decay
            weighted_sum += contribution
            signal_breakdown[sig.rule_name] = round(sig.value * decay, 4)

        # Base score from weights
        raw_score = weighted_sum * 100.0

        triggered_rules = list(rule_signals.keys())

        # 1. Base penalty for known ransomware extensions (+40)
        if "mass_rename" in triggered_rules:
            raw_score += 40.0

        # 2. Burst velocity penalty (+50)
        # Calculate max burst rate over the events in the window
        events = self._file_window.get_items()
        modify_events = [
            ts for ts, e in events
            if isinstance(e, RawFileEvent) and e.event_type in ("modified", "created", "renamed")
        ]
        
        burst_rate = 0.0
        if len(modify_events) > 1:
            modify_events.sort()
            duration = (modify_events[-1] - modify_events[0]).total_seconds()
            if duration > 0:
                burst_rate = len(modify_events) / duration
            else:
                burst_rate = float(len(modify_events))
                
        if burst_rate > 10.0 and ("mass_rename" in triggered_rules or "entropy" in triggered_rules):
            raw_score += 50.0

        # Scale to 0–100 and clamp
        raw_score = min(raw_score, 100.0)
        score = round(max(raw_score, 0.0), 2)
        severity = _classify_score(score)

        _log.debug(
            f"Score computed | score={score:.1f} | severity={severity} | "
            f"rules={triggered_rules}"
        )

        return ScoringResult(
            score=score,
            severity=severity,
            signals=signals,
            signal_breakdown=signal_breakdown,
            triggered_rules=triggered_rules,
            timestamp=now,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist_score(self, result: ScoringResult) -> None:
        """
        Write a ThreatScore ORM record to PostgreSQL.

        Args:
            result: The scoring result to persist.
        """
        window_start_ts = datetime.now(timezone.utc)
        record = ThreatScore(
            timestamp=result.timestamp,
            score=result.score,
            severity_level=result.severity,
            triggered_rules=result.triggered_rules,
            signal_breakdown=result.signal_breakdown,
            window_start=datetime.fromtimestamp(
                result.timestamp.timestamp() - self._window_seconds,
                tz=timezone.utc,
            ),
            window_end=result.timestamp,
        )

        try:
            alert_dict = None
            async with get_async_db_session() as session:
                session.add(record)
                await session.flush()
                
                # Dynamic Alert Titles Map
                RULE_TITLES = {
                    "mass_rename": "Mass File Rename to Suspicious Extension",
                    "file_rename": "High-Velocity File Modifications",
                    "entropy": "High-Entropy Files Created",
                    "process_chain": "Anomalous Resource Spike Detected",
                    "shadow_copy": "Shadow Copy Disruption Attempt",
                    "network_beacon": "Suspicious Network Beaconing",
                }
                
                # Alert Generation & Anti-Spam Logic
                now = datetime.now(timezone.utc)
                if result.score >= 70.0:
                    if self._last_alert_time is None or (now - self._last_alert_time).total_seconds() > 15:
                        self._last_alert_time = now
                        from backend.database.models import Alert
                        
                        titles = [RULE_TITLES.get(r, f"Rule: {r}") for r in result.triggered_rules]
                        title_str = " | ".join(titles) if titles else "High-Velocity Ransomware Behavior Detected"
                        
                        alert_record = Alert(
                            alert_type="CRITICAL_THREAT_DETECTED",
                            threat_score_id=record.id,
                            message=f"CRITICAL: {title_str} (Score: {result.score:.1f})",
                            raw_context=result.signal_breakdown
                        )
                        session.add(alert_record)
                        await session.commit()
                        await session.refresh(alert_record)
                        
                        alert_dict = {
                            "id": str(alert_record.id),
                            "timestamp": alert_record.timestamp.isoformat(),
                            "alert_type": alert_record.alert_type,
                            "threat_score_id": str(alert_record.threat_score_id),
                            "message": alert_record.message,
                            "acknowledged": alert_record.acknowledged,
                            "raw_context": alert_record.raw_context
                        }
                    else:
                        await session.commit()
                elif result.score < 40.0:
                    if self._last_heartbeat_time is None or (now - self._last_heartbeat_time).total_seconds() > 60:
                        self._last_heartbeat_time = now
                        from backend.database.models import Alert
                        
                        alert_record = Alert(
                            alert_type="NOMINAL_HEARTBEAT",
                            threat_score_id=record.id,
                            message=f"INFO: System State Nominal - Active Monitoring (Score: {result.score:.1f})",
                            raw_context={}
                        )
                        session.add(alert_record)
                        await session.commit()
                        await session.refresh(alert_record)
                        
                        alert_dict = {
                            "id": str(alert_record.id),
                            "timestamp": alert_record.timestamp.isoformat(),
                            "alert_type": alert_record.alert_type,
                            "threat_score_id": str(alert_record.threat_score_id),
                            "message": alert_record.message,
                            "acknowledged": alert_record.acknowledged,
                            "raw_context": alert_record.raw_context
                        }
                    else:
                        await session.commit()
                else:
                    await session.commit()
                    
            _log.debug(
                f"ThreatScore persisted | score={result.score:.1f} | "
                f"severity={result.severity}"
            )
            
            if alert_dict:
                from backend.api.routes.stream import publish_alert
                await publish_alert(alert_dict)
                
        except Exception as exc:
            _log.error(f"Failed to persist ThreatScore or Alert: {exc}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def current_score(self) -> float:
        """Return the most recently computed threat score."""
        return self._current_score

    @property
    def current_severity(self) -> str:
        """Return the most recently computed severity level."""
        return self._current_severity

    @property
    def is_running(self) -> bool:
        """Return True if the engine is active."""
        return self._running

    def get_score_history(self, last_n: int = 60) -> list[ScoringResult]:
        """
        Return the most recent N scoring results.

        Args:
            last_n: Maximum number of results to return.

        Returns:
            list[ScoringResult]: Ordered chronologically, most recent last.
        """
        history = list(self._score_history)
        return history[-last_n:]

    def get_status(self) -> dict[str, object]:
        """
        Return a status summary dict suitable for the /status API endpoint.

        Returns:
            dict: Keys: score, severity, running, file_queue_depth,
                  process_queue_depth, window_seconds.
        """
        return {
            "score": self._current_score,
            "severity": self._current_severity,
            "running": self._running,
            "file_queue_depth": self.file_queue.qsize(),
            "process_queue_depth": self.process_queue.qsize(),
            "window_seconds": self._window_seconds,
        }
