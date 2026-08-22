"""
backend/api/dependencies.py
============================
Shared FastAPI dependency functions for the RDRS API layer.

All dependencies are designed for use with FastAPI's ``Depends()`` injection
system. They provide:
  - Async database sessions (one per request, auto-committed / rolled back).
  - Access to the live engine and monitor singletons (set during app startup).
  - Pagination parameter parsing.

Usage:
    from backend.api.dependencies import get_db, get_engine, paginate

    @router.get("/events")
    async def list_events(
        db: AsyncSession = Depends(get_db),
        pagination: PaginationParams = Depends(paginate),
    ):
        ...
"""

from __future__ import annotations

from typing import AsyncGenerator

from fastapi import Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import PaginationParams
from backend.database.session import get_async_session

# ---------------------------------------------------------------------------
# Module-level singleton references — set during FastAPI lifespan startup
# ---------------------------------------------------------------------------
# These are populated by main.py's lifespan handler once the engine,
# monitor, and poller are initialized. Routes access them via dependencies.

_engine_instance = None       # ThreatScoringEngine
_monitor_instance = None      # FileSystemMonitor
_poller_instance = None       # ProcessPoller


def set_engine(engine: object) -> None:
    """Register the live ThreatScoringEngine singleton."""
    global _engine_instance
    _engine_instance = engine


def set_monitor(monitor: object) -> None:
    """Register the live FileSystemMonitor singleton."""
    global _monitor_instance
    _monitor_instance = monitor


def set_poller(poller: object) -> None:
    """Register the live ProcessPoller singleton."""
    global _poller_instance
    _poller_instance = poller




# ===========================================================================
# Database Session Dependency
# ===========================================================================


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields a per-request async database session.

    Commits on clean exit, rolls back on exception. Should be used in every
    route handler that needs database access.

    Yields:
        AsyncSession: An active SQLAlchemy async session.

    Example:
        @router.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(FileEvent))
            return result.scalars().all()
    """
    async for session in get_async_session():
        yield session


# ===========================================================================
# Pagination Dependency
# ===========================================================================


async def paginate(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=500, description="Items per page"),
) -> PaginationParams:
    """
    FastAPI dependency that parses pagination query parameters.

    Args:
        page:      Page number, 1-indexed.
        page_size: Number of items per page (max 500).

    Returns:
        PaginationParams: Validated pagination parameters.
    """
    return PaginationParams(page=page, page_size=page_size)


# ===========================================================================
# Engine / Monitor Accessor Dependencies
# ===========================================================================


def get_engine() -> object:
    """
    Return the live ThreatScoringEngine singleton.

    Returns:
        ThreatScoringEngine: The running scoring engine instance.

    Raises:
        RuntimeError: If the engine has not been initialized.
    """
    if _engine_instance is None:
        raise RuntimeError(
            "ThreatScoringEngine is not initialized. "
            "Ensure the FastAPI lifespan handler has started the engine."
        )
    return _engine_instance


def get_monitor() -> object:
    """
    Return the live FileSystemMonitor singleton.

    Returns:
        FileSystemMonitor: The running filesystem monitor instance.
    """
    if _monitor_instance is None:
        raise RuntimeError("FileSystemMonitor is not initialized.")
    return _monitor_instance


def get_poller() -> object:
    """
    Return the live ProcessPoller singleton.

    Returns:
        ProcessPoller: The running process poller instance.
    """
    if _poller_instance is None:
        raise RuntimeError("ProcessPoller is not initialized.")
    return _poller_instance



