"""
backend/api/routes/health.py
=============================
Health check and system status endpoints for the RDRS API.

Endpoints:
    GET /health  — Lightweight liveness probe (no auth required).
    GET /status  — Detailed engine and scoring status (auth required in prod).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, get_engine, get_monitor, get_poller
from backend.api.schemas import (
    DetectorWeightsOut,
    HealthOut,
    ScoringConfigOut,
    StatusOut,
)
from backend.core.config import settings
from backend.database.session import check_db_connectivity

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthOut,
    summary="Liveness probe",
    description=(
        "Lightweight health check endpoint. Returns the current operational status "
        "of the RDRS API, database connectivity, and background monitor states. "
        "This endpoint is unauthenticated and suitable for load balancer probes."
    ),
)
async def health_check(db: AsyncSession = Depends(get_db)) -> HealthOut:
    """
    Perform a liveness check on the RDRS API and its dependencies.

    Checks:
      - Database reachability (executes SELECT 1).
      - FileSystemMonitor running state.
      - ProcessPoller running state.

    Args:
        db: Injected async database session (validates DB connectivity).

    Returns:
        HealthOut: Health status payload.
    """
    db_ok = await check_db_connectivity()

    try:
        monitor = get_monitor()
        monitor_running = getattr(monitor, "is_running", False)
    except RuntimeError:
        monitor_running = False

    try:
        poller = get_poller()
        poller_running = getattr(poller, "is_running", False)
    except RuntimeError:
        poller_running = False

    overall = "ok" if (db_ok and monitor_running) else "degraded"

    return HealthOut(
        status=overall,  # type: ignore[arg-type]
        version=settings.app.version,
        timestamp=datetime.now(timezone.utc),
        database_reachable=db_ok,
        monitor_running=monitor_running,
        poller_running=poller_running,
    )


@router.get(
    "/status",
    response_model=StatusOut,
    summary="Detailed system status",
    description=(
        "Returns the current threat score, severity level, engine configuration, "
        "queue depths, and active watch paths. Designed for the SOC dashboard "
        "status panel."
    ),
)
async def system_status() -> StatusOut:
    """
    Return a detailed snapshot of the RDRS operational state.

    Sources data from:
      - The live ThreatScoringEngine (current score, severity, queue depths).
      - Application settings (watch paths, scoring config, response mode).

    Returns:
        StatusOut: Comprehensive system status payload.
    """
    try:
        engine = get_engine()
        engine_status: dict = getattr(engine, "get_status", lambda: {})()
        engine_running: bool = getattr(engine, "is_running", False)
        current_score: float = float(engine_status.get("score", 0.0))
        severity: str = str(engine_status.get("severity", "NOMINAL"))
        file_q: int = int(engine_status.get("file_queue_depth", 0))
        proc_q: int = int(engine_status.get("process_queue_depth", 0))
    except RuntimeError:
        engine_running = False
        current_score = 0.0
        severity = "NOMINAL"
        file_q = 0
        proc_q = 0

    weights = settings.threat_scoring.detector_weights
    watch_paths = [str(p) for p in settings.get_watch_paths()]

    return StatusOut(
        current_score=current_score,
        severity=severity,
        response_mode=settings.response.mode,
        file_queue_depth=file_q,
        process_queue_depth=proc_q,
        engine_running=engine_running,
        watch_paths=watch_paths,
        scoring_config=ScoringConfigOut(
            window_seconds=settings.threat_scoring.window_seconds,
            decay_lambda=settings.threat_scoring.decay_lambda,
            score_interval_seconds=5.0,
            weights=DetectorWeightsOut(
                file_rename=weights.file_rename,
                entropy=weights.entropy,
                process_chain=weights.process_chain,
                shadow_copy=weights.shadow_copy,
                network_beacon=weights.network_beacon,
            ),
        ),
        timestamp=datetime.now(timezone.utc),
    )
