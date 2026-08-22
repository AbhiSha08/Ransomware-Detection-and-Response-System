"""
backend/api/routes/alerts.py
=============================
Alert and Incident management endpoints for the RDRS API.

Endpoints:
    GET  /alerts                  — Paginated list of alerts.
    GET  /alerts/{id}             — Single alert detail.
    POST /alerts/{id}/dismiss     — Operator acknowledges an alert.
    GET  /incidents               — Paginated list of incidents.
    GET  /incidents/{id}          — Single incident detail.
    POST /incidents/{id}/resolve  — Operator resolves an incident.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, paginate
from backend.api.schemas import (
    AlertDismissIn,
    AlertOut,
    IncidentOut,
    IncidentResolveIn,
    PaginatedAlerts,
    PaginatedIncidents,
    PaginatedMeta,
)
from backend.core.logging import audit_log
from backend.database.models import Alert, Incident

router = APIRouter(tags=["Alerts & Incidents"])


# ===========================================================================
# Alert Endpoints
# ===========================================================================


@router.get(
    "/alerts",
    response_model=PaginatedAlerts,
    summary="List alerts",
    description=(
        "Returns a paginated list of Alert records. Supports filtering by "
        "acknowledgment status and alert type. Results are ordered by timestamp "
        "descending (newest first)."
    ),
)
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    pagination: PaginatedMeta = Depends(paginate),
    acknowledged: bool | None = Query(
        default=None,
        description="Filter by acknowledgment status. Omit for all alerts.",
    ),
    alert_type: str | None = Query(
        default=None,
        description="Filter by alert type (e.g., FILE_RENAME_SPIKE)",
    ),
) -> PaginatedAlerts:
    """
    Retrieve a paginated list of Alert records with optional filters.

    Args:
        db:           Async database session.
        pagination:   Page and page_size parameters.
        acknowledged: If provided, filter by acknowledgment status.
        alert_type:   If provided, filter by alert type string.

    Returns:
        PaginatedAlerts: Paginated list with metadata.
    """
    query = select(Alert).order_by(Alert.timestamp.desc())

    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type.upper())

    count_query = select(func.count()).select_from(query.subquery())
    total_count: int = (await db.execute(count_query)).scalar_one()

    paged_query = query.offset(pagination.offset).limit(pagination.page_size)
    rows = (await db.execute(paged_query)).scalars().all()

    total_pages = max(1, (total_count + pagination.page_size - 1) // pagination.page_size)

    return PaginatedAlerts(
        meta=PaginatedMeta(
            page=pagination.page,
            page_size=pagination.page_size,
            total_count=total_count,
            total_pages=total_pages,
        ),
        items=[AlertOut.model_validate(row) for row in rows],
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    summary="Get a single alert",
    description="Retrieve the full detail of a single Alert record by its UUID.",
)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """
    Retrieve a single Alert record by UUID.

    Args:
        alert_id: UUID of the target alert.
        db:       Async database session.

    Returns:
        AlertOut: Full alert detail.

    Raises:
        HTTPException 404: If no alert with the given ID exists.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )

    return AlertOut.model_validate(alert)


@router.post(
    "/alerts/{alert_id}/dismiss",
    response_model=AlertOut,
    summary="Dismiss an alert",
    description=(
        "Mark an alert as acknowledged by an operator. Once dismissed, the alert "
        "will no longer appear in the unacknowledged filter. This action is "
        "recorded in the audit log."
    ),
)
async def dismiss_alert(
    alert_id: UUID,
    body: AlertDismissIn,
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """
    Acknowledge and dismiss an Alert record.

    Records the operator identifier, timestamp, and optional notes.
    Writes an entry to the immutable audit log.

    Args:
        alert_id: UUID of the alert to dismiss.
        body:     Dismiss request body with operator ID and optional notes.
        db:       Async database session.

    Returns:
        AlertOut: Updated alert with acknowledgment fields populated.

    Raises:
        HTTPException 404: If no alert with the given ID exists.
        HTTPException 409: If the alert is already acknowledged.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )

    if alert.acknowledged:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert {alert_id} is already acknowledged.",
        )

    now = datetime.now(timezone.utc)
    alert.acknowledged = True
    alert.acknowledged_at = now
    alert.acknowledged_by = body.acknowledged_by

    # Append operator notes to raw_context if provided
    if body.notes:
        ctx = dict(alert.raw_context or {})
        ctx["operator_notes"] = body.notes
        alert.raw_context = ctx

    await db.flush()

    audit_log(
        action="ALERT_DISMISSED",
        details={
            "alert_id": str(alert_id),
            "operator": body.acknowledged_by,
            "timestamp": now.isoformat(),
        },
    )

    return AlertOut.model_validate(alert)


# ===========================================================================
# Incident Endpoints
# ===========================================================================


@router.get(
    "/incidents",
    response_model=PaginatedIncidents,
    summary="List incidents",
    description=(
        "Returns a paginated list of Incident records ordered by timestamp descending. "
        "Supports filtering by severity and resolution status."
    ),
)
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    pagination: PaginatedMeta = Depends(paginate),
    resolved: bool | None = Query(
        default=None,
        description="Filter by resolution status. Omit for all incidents.",
    ),
    severity: str | None = Query(
        default=None,
        description="Filter by severity level (e.g., CRITICAL, HIGH)",
    ),
) -> PaginatedIncidents:
    """
    Retrieve a paginated list of Incident records.

    Args:
        db:         Async database session.
        pagination: Page and page_size parameters.
        resolved:   Optional resolution status filter.
        severity:   Optional severity level filter.

    Returns:
        PaginatedIncidents: Paginated list with metadata.
    """
    query = select(Incident).order_by(Incident.timestamp.desc())

    if resolved is not None:
        query = query.where(Incident.resolved == resolved)
    if severity:
        query = query.where(Incident.severity_level == severity.upper())

    count_query = select(func.count()).select_from(query.subquery())
    total_count: int = (await db.execute(count_query)).scalar_one()

    paged_query = query.offset(pagination.offset).limit(pagination.page_size)
    rows = (await db.execute(paged_query)).scalars().all()

    total_pages = max(1, (total_count + pagination.page_size - 1) // pagination.page_size)

    return PaginatedIncidents(
        meta=PaginatedMeta(
            page=pagination.page,
            page_size=pagination.page_size,
            total_count=total_count,
            total_pages=total_pages,
        ),
        items=[IncidentOut.model_validate(row) for row in rows],
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentOut,
    summary="Get a single incident",
    description="Retrieve the full detail of a single Incident record by its UUID.",
)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """
    Retrieve a single Incident record by UUID.

    Args:
        incident_id: UUID of the target incident.
        db:          Async database session.

    Returns:
        IncidentOut: Full incident detail.

    Raises:
        HTTPException 404: If no incident with the given ID exists.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} not found.",
        )

    return IncidentOut.model_validate(incident)


@router.post(
    "/incidents/{incident_id}/resolve",
    response_model=IncidentOut,
    summary="Resolve an incident",
    description=(
        "Mark an Incident as resolved by an operator. Optionally attach post-incident "
        "analysis notes. Writes an immutable audit log entry."
    ),
)
async def resolve_incident(
    incident_id: UUID,
    body: IncidentResolveIn,
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    """
    Mark an Incident record as resolved.

    Args:
        incident_id: UUID of the incident to resolve.
        body:        Optional post-incident analysis notes.
        db:          Async database session.

    Returns:
        IncidentOut: Updated incident with resolved=True.

    Raises:
        HTTPException 404: If no incident with the given ID exists.
        HTTPException 409: If the incident is already resolved.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} not found.",
        )

    if incident.resolved:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident {incident_id} is already resolved.",
        )

    now = datetime.now(timezone.utc)
    incident.resolved = True
    incident.resolved_at = now
    if body.notes:
        incident.notes = body.notes

    await db.flush()

    audit_log(
        action="INCIDENT_RESOLVED",
        details={
            "incident_id": str(incident_id),
            "timestamp": now.isoformat(),
            "notes_provided": body.notes is not None,
        },
    )

    return IncidentOut.model_validate(incident)
