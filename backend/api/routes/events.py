"""
backend/api/routes/events.py
=============================
Filesystem event endpoints for the RDRS API.

Endpoints:
    GET /events           — Paginated, filterable list of FileEvent records.
    GET /events/{id}      — Single FileEvent detail by UUID.
    GET /scores/timeseries — Threat score time-series for dashboard charting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, paginate
from backend.api.schemas import (
    FileEventFilter,
    FileEventOut,
    PaginatedFileEvents,
    PaginatedMeta,
    ScoreTimeSeriesOut,
    ScoreTimeSeriesPoint,
    ThreatScoreOut,
)
from backend.database.models import FileEvent, ThreatScore

router = APIRouter(tags=["Events & Scores"])


@router.get(
    "/events",
    response_model=PaginatedFileEvents,
    summary="List filesystem events",
    description=(
        "Returns a paginated, filterable log of all FileEvent records captured "
        "by the watchdog monitor. Supports filtering by event type, file extension, "
        "minimum entropy score, and time range."
    ),
)
async def list_events(
    db: AsyncSession = Depends(get_db),
    pagination: PaginatedMeta = Depends(paginate),
    event_type: str | None = Query(default=None, description="Filter by event type"),
    extension: str | None = Query(default=None, description="Filter by file extension"),
    min_entropy: float | None = Query(default=None, ge=0.0, le=8.0),
    since: datetime | None = Query(default=None, description="Events after this UTC timestamp"),
    until: datetime | None = Query(default=None, description="Events before this UTC timestamp"),
) -> PaginatedFileEvents:
    """
    Retrieve a paginated list of filesystem events with optional filters.

    Args:
        db:         Async database session.
        pagination: Page and page_size parameters.
        event_type: Optional event type filter (created|modified|deleted|renamed).
        extension:  Optional file extension filter (e.g., .locked).
        min_entropy: Only return events where entropy_score >= this value.
        since:      Only return events after this UTC timestamp.
        until:      Only return events before this UTC timestamp.

    Returns:
        PaginatedFileEvents: Paginated list with metadata.
    """
    query = select(FileEvent).order_by(FileEvent.timestamp.desc())

    if event_type:
        query = query.where(FileEvent.event_type == event_type.lower())
    if extension:
        ext = extension if extension.startswith(".") else f".{extension}"
        query = query.where(FileEvent.file_extension == ext.lower())
    if min_entropy is not None:
        query = query.where(FileEvent.entropy_score >= min_entropy)
    if since:
        query = query.where(FileEvent.timestamp >= since)
    if until:
        query = query.where(FileEvent.timestamp <= until)

    # Total count for pagination metadata
    count_query = select(func.count()).select_from(query.subquery())
    total_count: int = (await db.execute(count_query)).scalar_one()

    # Apply pagination
    paged_query = query.offset(pagination.offset).limit(pagination.page_size)
    rows = (await db.execute(paged_query)).scalars().all()

    total_pages = max(1, (total_count + pagination.page_size - 1) // pagination.page_size)

    return PaginatedFileEvents(
        meta=PaginatedMeta(
            page=pagination.page,
            page_size=pagination.page_size,
            total_count=total_count,
            total_pages=total_pages,
        ),
        items=[FileEventOut.model_validate(row) for row in rows],
    )


@router.get(
    "/events/{event_id}",
    response_model=FileEventOut,
    summary="Get a single filesystem event",
    description="Retrieve the full detail of a single FileEvent record by its UUID.",
)
async def get_event(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> FileEventOut:
    """
    Retrieve a single FileEvent record by UUID.

    Args:
        event_id: UUID of the target event.
        db:       Async database session.

    Returns:
        FileEventOut: Full event detail.

    Raises:
        HTTPException 404: If no event with the given ID exists.
    """
    result = await db.execute(select(FileEvent).where(FileEvent.id == event_id))
    event = result.scalar_one_or_none()

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"FileEvent with id={event_id} not found.",
        )

    return FileEventOut.model_validate(event)


@router.get(
    "/scores/timeseries",
    response_model=ScoreTimeSeriesOut,
    summary="Threat score time series",
    description=(
        "Returns a time-series of threat score values for the specified window. "
        "Used by the dashboard's real-time score chart. Points are ordered "
        "chronologically (oldest first)."
    ),
)
async def scores_timeseries(
    db: AsyncSession = Depends(get_db),
    since: datetime | None = Query(
        default=None,
        description="Start of time range (UTC). Defaults to last 1 hour.",
    ),
    until: datetime | None = Query(
        default=None,
        description="End of time range (UTC). Defaults to now.",
    ),
    limit: int = Query(default=360, ge=1, le=2000, description="Max data points to return"),
) -> ScoreTimeSeriesOut:
    """
    Retrieve threat score time-series data for dashboard charting.

    Args:
        db:    Async database session.
        since: Start of the time window.
        until: End of the time window.
        limit: Maximum number of data points.

    Returns:
        ScoreTimeSeriesOut: Time-series with aggregate statistics.
    """
    query = select(ThreatScore).order_by(ThreatScore.timestamp.asc())

    if since:
        query = query.where(ThreatScore.timestamp >= since)
    if until:
        query = query.where(ThreatScore.timestamp <= until)

    query = query.limit(limit)
    rows = (await db.execute(query)).scalars().all()

    points = [
        ScoreTimeSeriesPoint(
            timestamp=row.timestamp,
            score=row.score,
            severity_level=row.severity_level,
        )
        for row in rows
    ]

    scores = [p.score for p in points] or [0.0]

    return ScoreTimeSeriesOut(
        points=points,
        total_points=len(points),
        min_score=min(scores),
        max_score=max(scores),
        avg_score=round(sum(scores) / len(scores), 2),
    )
