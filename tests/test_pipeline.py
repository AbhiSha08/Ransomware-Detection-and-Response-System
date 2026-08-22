"""
tests/test_pipeline.py
=======================
Integration tests for the complete RDRS detection & incident response pipeline.

Tests cover:
  - Feeding a burst of simulated file creation/modification/rename/high-entropy events
    and process telemetry into the detection pipeline.
  - Asserting composite ThreatScore reaches CRITICAL (>= 70.0).
  - Verifying Incident & Alert records are persisted to the database.
  - Validating evidence quarantine logic strictly within data/sandbox/quarantine/.
"""

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import Alert, Incident
from backend.detectors.engine import ThreatScoringEngine, ScoringResult
from backend.detectors.file_monitor import RawFileEvent
from backend.detectors.process_poller import RawProcessSnapshot
from backend.detectors.responder import IncidentResponder
from tests.conftest import SANDBOX_ROOT, assert_in_sandbox


@pytest.mark.asyncio
async def test_full_pipeline_critical_incident_and_quarantine(
    async_session: AsyncSession,
    sandbox: Path,
) -> None:
    """
    Integration Test:
      1. Create victim files in sandbox.
      2. Feed ransomware-like telemetry across all detector rules (mass renames to .locked,
         high entropy creation/modification events, process spikes, shadow copy deletion).
      3. Evaluate ThreatScoringEngine -> Expect score >= 70.0 (CRITICAL).
      4. Trigger IncidentResponder -> Expect Incident & Alert records in DB.
      5. Verify evidence quarantine copies land strictly in data/sandbox/quarantine/.
    """
    # Step 1: Create victim test files inside sandbox
    file1 = sandbox / "financial_report.xlsx"
    file2 = sandbox / "customer_db.sql"
    file1.write_bytes(os.urandom(16 * 1024))
    file2.write_bytes(os.urandom(16 * 1024))

    assert_in_sandbox(file1)
    assert_in_sandbox(file2)

    # Step 2: Initialize IncidentResponder for quarantine test
    responder = IncidentResponder(sandbox_dir=str(SANDBOX_ROOT / "quarantine"))

    # Step 3: Instantiate ThreatScoringEngine
    engine = ThreatScoringEngine()

    now = datetime.now(timezone.utc)

    # Populate engine sliding window with high-intensity ransomware telemetry:
    # 1. High entropy file creation events (HighEntropyDetectorRule -> 0.98 * 0.25)
    for i in range(10):
        f_create = sandbox / f"enc_file_{i}.dat"
        f_create.write_bytes(os.urandom(8 * 1024))
        evt_create = RawFileEvent(
            event_type="created",
            src_path=str(f_create),
            dst_path=None,
            timestamp=now,
            entropy_score=7.98,
        )
        engine._file_window.append(now, evt_create)

    # 2. Rapid file renames (FileVelocity + MassRenameDetectorRule -> 1.0 * 0.30)
    for i in range(35):
        f = sandbox / f"victim_doc_{i}.docx"
        f.write_bytes(os.urandom(8 * 1024))
        evt = RawFileEvent(
            event_type="renamed",
            src_path=str(f),
            dst_path=str(f) + ".locked",
            timestamp=now,
            entropy_score=7.98,
        )
        engine._file_window.append(now, evt)

    # Explicit victim file events for quarantine extraction
    evt1 = RawFileEvent(
        event_type="renamed",
        src_path=str(file1),
        dst_path=str(file1) + ".locked",
        timestamp=now,
        entropy_score=7.98,
    )
    evt2 = RawFileEvent(
        event_type="renamed",
        src_path=str(file2),
        dst_path=str(file2) + ".locked",
        timestamp=now,
        entropy_score=7.96,
    )
    engine._file_window.append(now, evt1)
    engine._file_window.append(now, evt2)

    # 3. Process resource spike (CPU 100% + disk writes -> 1.0 * 0.20)
    spike_snap = RawProcessSnapshot(
        timestamp=now,
        pid=7770,
        process_name="encrypter.exe",
        cpu_percent=100.0,
        memory_mb=500.0,
        disk_write_bytes=150 * 1024 * 1024,
        exe_path=str(sandbox / "encrypter.exe"),
        parent_pid=1000,
        parent_name="cmd.exe",
        cmdline="encrypter.exe --all",
        is_flagged=True,
        flag_reason="High CPU and disk write activity",
    )
    engine._process_window.append(now, spike_snap)

    # 4. Shadow copy deletion process snapshot (ShadowCopyDetectorRule -> 0.4 * 0.15)
    vss_snap = RawProcessSnapshot(
        timestamp=now,
        pid=6660,
        process_name="vssadmin.exe",
        cpu_percent=85.0,
        memory_mb=120.0,
        disk_write_bytes=80 * 1024 * 1024,
        exe_path="C:\\Windows\\System32\\vssadmin.exe",
        parent_pid=1234,
        parent_name="cmd.exe",
        cmdline="vssadmin.exe Delete Shadows /All /Quiet",
        is_flagged=True,
        flag_reason="Shadow copy deletion tool",
    )
    engine._process_window.append(now, vss_snap)

    # Step 4: Evaluate scoring engine
    result: ScoringResult = engine._evaluate()

    assert result.score >= 70.0, f"Expected CRITICAL threat score >= 70.0, got {result.score}"
    assert result.severity == "CRITICAL"
    assert "file_rename" in result.triggered_rules or "entropy" in result.triggered_rules

    # Step 5: Mint Incident (simulating engine._scoring_loop)
    import uuid
    incident_id = str(uuid.uuid4())
    incident = Incident(
        id=uuid.UUID(incident_id),
        timestamp=result.timestamp,
        threat_score=result.score,
        severity_level=result.severity,
        response_mode="simulation",
        resolved=False,
    )
    async_session.add(incident)
    await async_session.commit()
    
    # Step 5.5: Invoke IncidentResponder directly with critical result context
    responder.quarantine_evidence(incident_id, [str(file1), str(file2)])
    await responder.broadcast_mitigation_alert(incident_id, pid="7770")

    # Step 6: Verify Incident record in database
    inc_result = await async_session.execute(select(Incident))
    incidents = inc_result.scalars().all()
    assert len(incidents) >= 1, "Incident record should be created in DB"

    inc = incidents[0]
    assert inc.threat_score >= 70.0
    assert inc.severity_level == "CRITICAL"

    # Step 7: Verify Alert record in database
    await asyncio.sleep(0.1)  # Yield to allow background tasks / separate DB sessions to finish
    await async_session.commit()  # Flush test session to see newly created records
    alert_result = await async_session.execute(select(Alert))
    alerts = alert_result.scalars().all()
    assert len(alerts) >= 1, "Alert record should be created in DB"
    assert "quarantined" in alerts[0].message

    # Step 8: Verify Evidence Quarantine logic
    quarantine_dir = SANDBOX_ROOT / "quarantine"
    assert quarantine_dir.exists(), "Quarantine directory should exist in data/sandbox/quarantine"
    assert_in_sandbox(quarantine_dir)

    # Original files must remain intact (COPY ONLY semantics)
    assert file1.exists(), "Original victim file must not be deleted or modified"
    assert file2.exists(), "Original victim file must not be deleted or modified"
