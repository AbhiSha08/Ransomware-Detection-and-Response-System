"""
tests/test_integration.py
=======================
Integration tests for the complete RDRS detection & incident response pipeline.

Tests cover:
  - Feeding a rapid burst of 50 simulated file creation/modification/rename/high-entropy events
  - Asserting composite ThreatScore reaches CRITICAL (>= 70.0).
  - Verifying IncidentResponder is invoked to quarantine the simulated files.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import Alert, Incident
from backend.detectors.engine import ThreatScoringEngine, ScoringResult
from backend.detectors.file_monitor import RawFileEvent
from backend.detectors.responder import IncidentResponder
from tests.conftest import SANDBOX_ROOT, assert_in_sandbox

@pytest.mark.asyncio
async def test_full_pipeline_critical_incident_and_quarantine(
    async_session: AsyncSession,
    sandbox: Path,
) -> None:
    # Step 1: Create victim test files inside sandbox
    files_to_quarantine = []
    for i in range(50):
        victim = sandbox / f"victim_file_{i}.docx"
        victim.write_bytes(os.urandom(16 * 1024))  # 16 KB of high-entropy data
        files_to_quarantine.append(str(victim.resolve()))
        assert_in_sandbox(victim)

    # Step 2: Initialize IncidentResponder
    responder = IncidentResponder(sandbox_dir=str(SANDBOX_ROOT / "quarantine"))

    # Step 3: Instantiate ThreatScoringEngine
    engine = ThreatScoringEngine()

    now = datetime.now(timezone.utc)

    # Populate engine sliding window with a rapid burst of 50 .locked file renames 
    # and high-entropy writes
    for i in range(50):
        evt = RawFileEvent(
            event_type="renamed",
            src_path=files_to_quarantine[i],
            dst_path=files_to_quarantine[i] + ".locked",
            timestamp=now,
            entropy_score=7.99,
        )
        engine._file_window.append(now, evt)

    # Step 4: Evaluate scoring engine
    result: ScoringResult = engine._evaluate()

    # Step 5: Assert that this burst successfully triggers a CRITICAL incident score
    assert result.score >= 70.0, f"Expected CRITICAL threat score >= 70.0, got {result.score}"
    assert result.severity == "CRITICAL"

    # Step 6: Invoke responder.py to quarantine the simulated files
    incident_id = "test-incident-123"
    responder.quarantine_evidence(incident_id, files_to_quarantine)
    await responder.broadcast_mitigation_alert(incident_id, pid="9999")

    # Step 7: Verify Evidence Quarantine logic
    quarantine_dir = SANDBOX_ROOT / "quarantine" / incident_id
    assert quarantine_dir.exists(), "Quarantine directory should exist"
    
    # Original files must remain intact (COPY ONLY semantics)
    for i in range(50):
        victim = sandbox / f"victim_file_{i}.docx"
        assert victim.exists(), "Original victim file must not be deleted or modified"
        
        quarantined_copy = quarantine_dir / f"victim_file_{i}.docx.quarantined"
        assert quarantined_copy.exists(), f"Quarantined copy {quarantined_copy} should exist"
