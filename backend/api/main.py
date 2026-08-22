"""
backend/api/main.py
====================
FastAPI application factory for the RDRS REST API.

This module:
  1. Constructs the FastAPI application with metadata, OpenAPI config, and lifespan.
  2. Configures strict CORS policies.
  3. Attaches slowapi rate limiting middleware.
  4. Registers all route modules under /api/v1/.
  5. Manages the startup/shutdown lifecycle of all RDRS background services
     (database init, engine, monitor, poller, SSE broadcaster).

Startup order:
    Database init → Logging setup → ThreatScoringEngine →
    FileSystemMonitor → ProcessPoller → SSE Broadcaster

Shutdown order (reverse):
    SSE Broadcaster → ProcessPoller → FileSystemMonitor →
    ThreatScoringEngine → DB pool disposal

Entry point:
    uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from backend.api import dependencies
from backend.api.routes import alerts, analyze, events, health, reports, scan, simulate, stream, reset
from backend.core.config import settings
from backend.core.logging import intercept_stdlib_logging, setup_logging
from backend.database.init_db import initialize_database
from backend.database.session import (
    check_db_connectivity,
    dispose_async_engine,
    dispose_sync_engine,
)
from backend.detectors.engine import ThreatScoringEngine
from backend.detectors.file_monitor import FileSystemMonitor
from backend.detectors.process_poller import ProcessPoller

# ===========================================================================
# Rate Limiter Setup
# ===========================================================================

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.api.rate_limit.default_limit],
    enabled=settings.api.rate_limit.enabled,
)

# ===========================================================================
# Lifespan Context Manager
# ===========================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan context manager that manages the full RDRS service lifecycle.

    Startup sequence (in order):
      1. Initialize logging subsystem.
      2. Intercept stdlib logging from third-party libraries.
      3. Initialize database schema (idempotent).
      4. Instantiate and start ThreatScoringEngine.
      5. Instantiate and start FileSystemMonitor.
      6. Instantiate and start ProcessPoller.
      7. Start SSE broadcaster background task.
      8. Register all singleton dependencies.

    Shutdown sequence (reverse order):
      - Stop SSE broadcaster.
      - Stop ProcessPoller.
      - Stop FileSystemMonitor.
      - Stop ThreatScoringEngine.
      - Dispose DB connection pools.

    Args:
        app: The FastAPI application instance.

    Yields:
        None: Control is yielded to FastAPI once startup is complete.
    """
    # ------------------------------------------------------------------
    # STARTUP
    # ------------------------------------------------------------------
    logger.info("=" * 60)
    logger.info(f"  {settings.app.name} v{settings.app.version}")
    logger.info(f"  Environment : {settings.app.environment}")
    logger.info(f"  Response Mode: {settings.response.mode.upper()}")
    logger.info("=" * 60)

    # Step 1: Logging subsystem
    setup_logging(
        level=settings.logging.level,
        log_format=settings.logging.format,
        rotation_size=settings.logging.rotation.size,
        retention=settings.logging.rotation.retention,
        compression=settings.logging.rotation.compression,
        diagnose=settings.logging.diagnose,
        backtrace=settings.logging.backtrace,
    )
    intercept_stdlib_logging(
        libraries=["sqlalchemy.engine", "uvicorn", "watchdog", "slowapi"],
        level=20,  # INFO
    )
    logger.success("Logging subsystem initialized.")

    # Step 2: Database
    logger.info("Initializing database schema...")
    db_ok = initialize_database(wait_for_db=True, max_retries=5, retry_delay=2.0)
    if not db_ok:
        logger.critical("Database initialization failed. Aborting startup.")
        raise RuntimeError("Database initialization failed — check PostgreSQL connection.")

    # Step 4: Scoring Engine
    scoring_engine = ThreatScoringEngine(
        score_interval=1.0,
    )
    await scoring_engine.start()
    dependencies.set_engine(scoring_engine)

    # Step 5: Filesystem Monitor
    file_monitor = FileSystemMonitor(event_queue=scoring_engine.file_queue)
    await file_monitor.start()
    dependencies.set_monitor(file_monitor)

    # Step 6: Process Poller
    process_poller = ProcessPoller(event_queue=scoring_engine.process_queue)
    await process_poller.start()
    dependencies.set_poller(process_poller)

    # Step 7: SSE Broadcaster
    stream.start_broadcaster()

    logger.success(
        f"RDRS API fully initialized | "
        f"db=ok | engine=running | monitor=running | poller=running | sse=broadcasting"
    )
    logger.info(f"API docs: http://{settings.api.host}:{settings.api.port}/docs")

    # Yield to FastAPI — application is now serving requests
    yield

    # ------------------------------------------------------------------
    # SHUTDOWN
    # ------------------------------------------------------------------
    logger.info("RDRS API shutting down...")

    await stream.stop_broadcaster()
    await process_poller.stop()
    await file_monitor.stop()
    await scoring_engine.stop()
    await dispose_async_engine()
    dispose_sync_engine()

    logger.success("RDRS API shutdown complete.")


# ===========================================================================
# FastAPI Application Factory
# ===========================================================================


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Registers:
      - OpenAPI metadata
      - Lifespan handler
      - CORS middleware
      - Rate limiting middleware
      - Global exception handlers
      - All API route modules under /api/v1/

    Returns:
        FastAPI: The configured application instance.
    """
    app = FastAPI(
        title=settings.app.name,
        description=(
            "**RDRS** — A real-time behavioral detection system that monitors "
            "filesystem and process activity to identify ransomware-like patterns.\n\n"
            "All endpoints are read-only with respect to the monitored host. "
            "The system is **strictly defensive** — no malware execution, "
            "no file modification, no process termination by default.\n\n"
            f"**Response Mode:** `{settings.response.mode.upper()}`"
        ),
        version=settings.app.version,
        openapi_url="/api/v1/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
        contact={
            "name": "RDRS Security Team",
            "email": "soc-team@yourdomain.com",
        },
        license_info={
            "name": "Internal Use Only",
            "url": "https://github.com/your-org/rdrs",
        },
    )

    # ------------------------------------------------------------------
    # Rate Limiter State
    # ------------------------------------------------------------------
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # CORS Middleware — strict allowlist, no wildcards
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
        expose_headers=["X-Total-Count", "X-Page", "X-Page-Size"],
        max_age=600,
    )

    # ------------------------------------------------------------------
    # Rate Limiting Middleware
    # ------------------------------------------------------------------
    app.add_middleware(SlowAPIMiddleware)

    # ------------------------------------------------------------------
    # Global Exception Handlers
    # ------------------------------------------------------------------

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Return a structured 500 error for any unhandled exception."""
        logger.exception(f"Unhandled exception on {request.method} {request.url}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Check server logs.",
                "detail": str(exc) if settings.app.debug else None,
            },
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
        """Return a structured 404 error."""
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "NOT_FOUND",
                "message": f"Resource not found: {request.url.path}",
                "detail": None,
            },
        )

    # ------------------------------------------------------------------
    # Route Registration — all routes under /api/v1/
    # ------------------------------------------------------------------
    API_PREFIX = "/api/v1"

    app.include_router(health.router, prefix=API_PREFIX)
    app.include_router(events.router, prefix=API_PREFIX)
    app.include_router(alerts.router, prefix=API_PREFIX)
    app.include_router(scan.router, prefix=API_PREFIX)
    app.include_router(reports.router, prefix=API_PREFIX)
    app.include_router(simulate.router, prefix=API_PREFIX)
    app.include_router(analyze.router, prefix=API_PREFIX)
    app.include_router(stream.router, prefix=API_PREFIX)
    app.include_router(reset.router, prefix=API_PREFIX)

    # Root redirect to docs
    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse(
            content={
                "service": settings.app.name,
                "version": settings.app.version,
                "docs": "/docs",
                "status": "/api/v1/health",
                "stream": "/api/v1/stream",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    return app


# ===========================================================================
# Application Singleton
# ===========================================================================

app = create_app()
