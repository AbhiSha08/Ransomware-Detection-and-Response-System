"""
backend/api/routes/reports.py
==============================
Report generation and retrieval endpoints for the RDRS API.

Endpoints:
    GET  /reports              — List previously generated report manifests.
    POST /reports/generate     — Generate a new incident report (JSON/CSV/PDF).
    GET  /reports/{incident_id} — Download a specific report file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db
from backend.api.schemas import ReportGenerateIn, ReportOut
from backend.core.logging import get_logger
from backend.database.models import Incident
from backend.reports.generator import ReportGenerator

_log = get_logger(__name__)
router = APIRouter(tags=["Reports"])

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_REPORTS_DIR = _PROJECT_ROOT / "data" / "reports"


@router.get(
    "/reports",
    summary="List generated reports",
    description=(
        "Returns a list of report manifest files found in the data/reports directory. "
        "Each entry includes the incident ID, formats available, and generation timestamp."
    ),
)
async def list_reports() -> list[dict]:
    """
    List all previously generated report manifests.

    Scans the data/reports directory for manifest.json files and returns
    their contents as a list of report metadata objects.

    Returns:
        list[dict]: List of report manifest dicts.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    manifests: list[dict] = []

    for manifest_path in sorted(_REPORTS_DIR.glob("*/manifest.json"), reverse=True):
        try:
            content = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifests.append(content)
        except Exception as exc:
            _log.warning(f"Failed to read report manifest: {manifest_path} | {exc}")
            continue

    return manifests


@router.post(
    "/reports/generate",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an incident report",
    description=(
        "Generate a post-incident report for a specified Incident record. "
        "Supports JSON, CSV, and PDF output formats. "
        "The report includes a file event timeline, threat score, process metadata, "
        "and remediation recommendations. PDF reports use a professional SOC layout."
    ),
)
async def generate_report(
    body: ReportGenerateIn,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    """
    Generate a post-incident analysis report in one or more formats.

    Fetches the Incident and its related file events, then delegates to
    ReportGenerator for rendering. The report is saved in data/reports/<incident_id>/.

    Args:
        body:             Report generation request with incident ID and format list.
        background_tasks: FastAPI background task runner.
        db:               Async database session.

    Returns:
        ReportOut: Metadata of the generated report including file paths and SHA-256 hashes.

    Raises:
        HTTPException 404: If the incident does not exist.
        HTTPException 500: If report generation fails.
    """
    result = await db.execute(
        select(Incident).where(Incident.id == body.incident_id)
    )
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={body.incident_id} not found.",
        )

    generator = ReportGenerator(db=db)

    try:
        report_out = await generator.generate(
            incident=incident,
            formats=body.formats,
            include_event_timeline=body.include_event_timeline,
            include_process_metadata=body.include_process_metadata,
            include_remediation=body.include_remediation,
        )
    except Exception as exc:
        _log.exception(f"Report generation failed for incident {body.incident_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        )

    _log.success(
        f"Report generated | incident={body.incident_id} | "
        f"formats={body.formats} | files={list(report_out.file_paths.values())}"
    )

    return report_out


@router.get(
    "/reports/{incident_id}",
    summary="Download a report file",
    description=(
        "Download a specific generated report file for an incident. "
        "The format query parameter selects which file to return. "
        "Defaults to JSON if available."
    ),
)
async def download_report(
    incident_id: UUID,
    fmt: str = "json",
) -> FileResponse:
    """
    Download a generated report file for a specific incident.

    Args:
        incident_id: UUID of the Incident whose report to download.
        fmt:         File format to download: 'json', 'csv', or 'pdf'.

    Returns:
        FileResponse: The report file as a download attachment.

    Raises:
        HTTPException 400: If the format string is invalid.
        HTTPException 404: If no report exists for this incident or format.
    """
    valid_formats = {"json", "csv", "pdf"}
    if fmt.lower() not in valid_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format '{fmt}'. Must be one of: {sorted(valid_formats)}",
        )

    incident_dir = _REPORTS_DIR / str(incident_id)
    if not incident_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No report found for incident {incident_id}.",
        )

    report_file = incident_dir / f"report.{fmt.lower()}"
    if not report_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Report in format '{fmt}' not found for incident {incident_id}. "
                f"Available formats can be found in the manifest: "
                f"GET /reports to see generated formats."
            ),
        )

    media_types = {
        "json": "application/json",
        "csv":  "text/csv",
        "pdf":  "application/pdf",
    }

    return FileResponse(
        path=str(report_file),
        filename=f"rdrs_incident_{incident_id}.{fmt}",
        media_type=media_types[fmt.lower()],
    )
