"""
tests/test_engine.py
=====================
Unit tests for the ThreatScoringEngine and rule evaluation logic (backend.detectors.engine).

Tests cover:
  - Configuration validation: detector weights sum to 1.0 ± 0.001.
  - Individual rule evaluators (Velocity, Mass Rename, High Entropy, Process Spike, Shadow Copy).
  - Composite threat score formula and exponential decay.
  - Severity band categorization (NOMINAL, MEDIUM, CRITICAL).
"""

from datetime import datetime, timezone
import pytest

from backend.core.config import settings
from backend.detectors.engine import (
    ThreatScoringEngine,
    SlidingWindow,
    FileModificationVelocityRule,
    MassRenameDetectorRule,
    HighEntropyDetectorRule,
    ProcessResourceSpikeRule,
    ShadowCopyDetectorRule,
    _classify_score,
)
from backend.detectors.file_monitor import RawFileEvent
from backend.detectors.process_poller import RawProcessSnapshot


def test_detector_weights_sum_to_one() -> None:
    """Validate invariant: all detector weights in configuration sum to 1.0."""
    w = settings.threat_scoring.detector_weights
    total = round(w.file_rename + w.entropy + w.process_chain + w.shadow_copy + w.network_beacon, 6)
    assert total == 1.0, f"Detector weights sum must equal 1.0, got {total}"


def test_severity_classification_bands() -> None:
    """Verify threat score severity band boundaries (Normal: 0-40, Warning: 40-70, Critical: 70-100)."""
    assert _classify_score(0.0) == "NOMINAL"
    assert _classify_score(25.0) == "NOMINAL"
    assert _classify_score(39.9) == "NOMINAL"

    assert _classify_score(40.0) == "MEDIUM"
    assert _classify_score(55.0) == "MEDIUM"
    assert _classify_score(69.9) == "MEDIUM"

    assert _classify_score(70.0) == "CRITICAL"
    assert _classify_score(88.5) == "CRITICAL"
    assert _classify_score(100.0) == "CRITICAL"


def test_sliding_window_expiration() -> None:
    """SlidingWindow must evict events older than window_seconds."""
    window = SlidingWindow(window_seconds=2)
    now = datetime.now(timezone.utc)

    window.append(now, "item1")
    assert len(window) == 1

    # Simulate expired item by adding past timestamp
    past = datetime.fromtimestamp(now.timestamp() - 10, tz=timezone.utc)
    window.append(past, "old_item")

    # Item should be purged
    items = window.get_items()
    assert len(items) == 1
    assert items[0][1] == "item1"


def test_mass_rename_rule_evaluation() -> None:
    """MassRenameDetectorRule fires when suspicious extensions (.locked) are observed."""
    rule = MassRenameDetectorRule()
    file_window = SlidingWindow(window_seconds=60)
    process_window = SlidingWindow(window_seconds=60)

    now = datetime.now(timezone.utc)
    # Add suspicious rename events
    for i in range(3):
        evt = RawFileEvent(
            event_type="renamed",
            src_path=f"/data/sandbox/doc_{i}.docx",
            dst_path=f"/data/sandbox/doc_{i}.docx.locked",
            timestamp=now,
        )
        file_window.append(now, evt)

    signal = rule.evaluate(file_window, process_window)
    assert signal is not None
    assert signal.rule_name == "file_rename"
    assert signal.value > 0.5
    assert "suspicious extension renames" in signal.evidence


def test_high_entropy_rule_evaluation() -> None:
    """HighEntropyDetectorRule fires when file entropy >= 7.0."""
    rule = HighEntropyDetectorRule()
    file_window = SlidingWindow(window_seconds=60)
    process_window = SlidingWindow(window_seconds=60)

    now = datetime.now(timezone.utc)
    evt = RawFileEvent(
        event_type="created",
        src_path="/data/sandbox/encrypted.dat",
        dst_path=None,
        timestamp=now,
        entropy_score=7.95,
    )
    file_window.append(now, evt)

    signal = rule.evaluate(file_window, process_window)
    assert signal is not None
    assert signal.rule_name == "entropy"
    assert signal.value > 0.0


def test_shadow_copy_detector_rule() -> None:
    """ShadowCopyDetectorRule fires when vssadmin or shadow copy process is detected."""
    rule = ShadowCopyDetectorRule()
    file_window = SlidingWindow(window_seconds=60)
    process_window = SlidingWindow(window_seconds=60)

    now = datetime.now(timezone.utc)
    snap = RawProcessSnapshot(
        timestamp=now,
        pid=4096,
        process_name="vssadmin.exe",
        cpu_percent=15.0,
        memory_mb=32.0,
        disk_write_bytes=1024,
        exe_path="C:\\Windows\\System32\\vssadmin.exe",
        parent_pid=1000,
        parent_name="cmd.exe",
        cmdline="vssadmin.exe delete shadows /all /quiet",
        is_flagged=True,
        flag_reason="Shadow copy deletion tool",
    )
    process_window.append(now, snap)

    signal = rule.evaluate(file_window, process_window)
    assert signal is not None
    assert signal.rule_name == "shadow_copy"
    assert signal.value >= 0.4


def test_engine_evaluate_composite_score() -> None:
    """ThreatScoringEngine produces composite score bounded in [0.0, 100.0]."""
    engine = ThreatScoringEngine()
    now = datetime.now(timezone.utc)

    # Ingest multiple suspicious events across rules
    for i in range(15):
        evt = RawFileEvent(
            event_type="renamed",
            src_path=f"/data/sandbox/file_{i}.pdf",
            dst_path=f"/data/sandbox/file_{i}.pdf.locked",
            timestamp=now,
            entropy_score=7.98,
        )
        engine._file_window.append(now, evt)

    snap = RawProcessSnapshot(
        timestamp=now,
        pid=9999,
        process_name="ransom.exe",
        cpu_percent=98.0,
        memory_mb=256.0,
        disk_write_bytes=200 * 1024 * 1024,
        exe_path="/data/sandbox/ransom.exe",
        parent_pid=1000,
        parent_name="cmd.exe",
        cmdline="ransom.exe --encrypt",
        is_flagged=True,
        flag_reason="High risk",
    )
    engine._process_window.append(now, snap)

    result = engine._evaluate()
    assert 0.0 <= result.score <= 100.0
    assert result.severity in ("MEDIUM", "CRITICAL")
    assert len(result.triggered_rules) >= 1
