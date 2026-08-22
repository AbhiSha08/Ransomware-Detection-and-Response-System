import shutil
from pathlib import Path
from loguru import logger as _log
from backend.database.session import get_async_db_session
from backend.database.models import Alert
from backend.api.routes.stream import publish_alert

class IncidentResponder:
    """
    Automated Incident Response Playbook for RDRS.
    Operates strictly in Simulation Mode.
    """

    def __init__(self, sandbox_dir: str = "data/sandbox/quarantine"):
        self.sandbox_dir = Path(sandbox_dir)

    def quarantine_evidence(self, incident_id: str, file_paths: list[str]) -> None:
        """
        Securely copy affected files to the quarantine sandbox.
        Appends .quarantined to the destination filenames.
        Preserves original file metadata via shutil.copy2.
        """
        incident_sandbox = self.sandbox_dir / str(incident_id)
        
        try:
            incident_sandbox.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _log.error(f"Failed to create quarantine directory for incident {incident_id}: {e}")
            return

        for path_str in file_paths:
            src_path = Path(path_str)
            if not src_path.exists() or not src_path.is_file():
                continue

            # Append .quarantined to the destination filename
            dest_filename = f"{src_path.name}.quarantined"
            dest_path = incident_sandbox / dest_filename

            try:
                # shutil.copy2 preserves file metadata (timestamps, etc.)
                shutil.copy2(src_path, dest_path)
                _log.info(f"Quarantined evidence: {src_path} -> {dest_path}")
            except PermissionError:
                _log.warning(f"File-lock permission error while trying to quarantine {src_path}. Skipping.")
            except Exception as e:
                _log.error(f"Failed to quarantine {src_path}: {e}")

    def simulate_neutralization(self, pid: str) -> None:
        """
        Simulate process termination in Defensive Mode without actually killing any system processes.
        """
        _log.bind(alert=True).warning(
            f"[SIMULATION - DEFENSIVE MODE] Automated Playbook Executed. Simulated termination of suspect PID: {pid}"
        )

    async def broadcast_mitigation_alert(self, incident_id: str, pid: str) -> None:
        """
        Generate and broadcast a specialized SOAR playbook alert via SSE.
        """
        quarantine_path = f"data/sandbox/quarantine/{incident_id}"
        message = f"Evidence successfully quarantined. Simulated termination of suspect PID: {pid}."
        
        try:
            alert_record = Alert(
                alert_type="SOAR_PLAYBOOK_EXECUTED",
                threat_score_id=None,
                message=message,
                raw_context={"quarantine_path": quarantine_path}
            )
            
            async with get_async_db_session() as session:
                session.add(alert_record)
                await session.commit()
                await session.refresh(alert_record)
                
            alert_dict = {
                "id": str(alert_record.id),
                "timestamp": alert_record.timestamp.isoformat(),
                "alert_type": alert_record.alert_type,
                "threat_score_id": None,
                "message": alert_record.message,
                "acknowledged": alert_record.acknowledged,
                "raw_context": alert_record.raw_context
            }
            await publish_alert(alert_dict)
            _log.info(f"Broadcasted SOAR mitigation alert for incident {incident_id}")
        except Exception as e:
            _log.error(f"Failed to broadcast SOAR mitigation alert: {e}")
