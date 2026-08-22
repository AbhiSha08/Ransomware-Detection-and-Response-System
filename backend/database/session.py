"""
backend/database/session.py
===========================
SQLAlchemy engine creation and session lifecycle management for the RDRS application.

This module provides:
  - Synchronous engine + session (used by background monitoring threads and CLI tools)
  - Asynchronous engine + session (used by FastAPI request handlers)
  - Context manager helpers for safe, exception-aware session usage
  - A `get_async_session` FastAPI dependency for dependency injection

Design Decisions:
  - The sync engine uses NullPool in test environments to prevent connection leaks
    between test cases.
  - The async engine uses AsyncAdaptedQueuePool for high-throughput FastAPI routes.
  - All sessions are configured with `expire_on_commit=False` to avoid lazy-load
    errors on detached instances returned from async endpoints.
  - The database URL is sourced exclusively from `settings` (never hardcoded).
  - Health-check logic is included to verify connectivity at startup.

Usage (synchronous):
    from backend.database.session import SyncSessionLocal

    with SyncSessionLocal() as session:
        session.add(some_model_instance)
        session.commit()

Usage (asynchronous / FastAPI):
    from backend.database.session import get_async_session
    from sqlalchemy.ext.asyncio import AsyncSession

    async def my_endpoint(db: AsyncSession = Depends(get_async_session)):
        result = await db.execute(select(FileEvent))
        ...
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator

from loguru import logger
from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from backend.core.config import settings

# ---------------------------------------------------------------------------
# Internal state — module-level singletons, initialized lazily
# ---------------------------------------------------------------------------
_sync_engine = None
_async_engine: AsyncEngine | None = None
_SyncSession: sessionmaker | None = None  # type: ignore[type-arg]
_AsyncSession: async_sessionmaker[AsyncSession] | None = None


# ===========================================================================
# Synchronous Engine & Session
# ===========================================================================


def _build_sync_engine():  # type: ignore[return]
    """
    Build and configure the synchronous SQLAlchemy engine.

    Uses QueuePool for production workloads and NullPool in test environments
    (detected via the RDRS_TEST_MODE env variable) to prevent connection leaks.

    Returns:
        sqlalchemy.engine.Engine: The configured sync engine.
    """
    import os

    pool_class = NullPool if os.getenv("RDRS_TEST_MODE", "").lower() == "true" else QueuePool
    pool_cfg = settings.database.pool

    engine = create_engine(
        settings.get_sync_db_url(),
        poolclass=pool_class,
        pool_size=pool_cfg.pool_size if pool_class is QueuePool else 0,
        max_overflow=pool_cfg.max_overflow if pool_class is QueuePool else 0,
        pool_timeout=pool_cfg.pool_timeout,
        pool_recycle=pool_cfg.pool_recycle,
        echo=pool_cfg.echo,
        # Ensure returned connections are alive before use
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 10,
            "application_name": "RDRS-sync",
        },
    )

    # Log pool checkout/checkin events at TRACE level (extremely verbose — dev only)
    if settings.app.debug:
        @event.listens_for(engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):  # type: ignore[misc]
            logger.trace("DB connection checked out from pool.")

        @event.listens_for(engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):  # type: ignore[misc]
            logger.trace("DB connection returned to pool.")

    logger.debug(
        f"Sync SQLAlchemy engine created | pool={pool_class.__name__} "
        f"| host={settings.db_host}:{settings.db_port}/{settings.db_name}"
    )
    return engine


def get_sync_engine():  # type: ignore[return]
    """
    Return the module-level synchronous engine singleton, creating it on
    first call (lazy initialization).

    Returns:
        sqlalchemy.engine.Engine: The global sync engine.
    """
    global _sync_engine
    if _sync_engine is None:
        _sync_engine = _build_sync_engine()
    return _sync_engine


def get_sync_session_factory() -> sessionmaker:  # type: ignore[type-arg]
    """
    Return the synchronous session factory, creating it on first call.

    Returns:
        sessionmaker: A factory that produces Session instances.
    """
    global _SyncSession
    if _SyncSession is None:
        _SyncSession = sessionmaker(
            bind=get_sync_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,  # Prevents lazy-load on detached instances
        )
    return _SyncSession


# Convenience alias used by monitoring background threads
SyncSessionLocal = get_sync_session_factory


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager that provides a transactional database session.

    Automatically commits on success and rolls back on any exception.
    Always closes the session in the finally block to return the
    connection to the pool.

    Yields:
        sqlalchemy.orm.Session: An active database session.

    Raises:
        Exception: Re-raises any exception after performing rollback.

    Example:
        with get_db_session() as session:
            session.add(file_event)
            # auto-committed on exit
    """
    factory = get_sync_session_factory()
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("DB session rolled back due to exception.")
        raise
    finally:
        session.close()


# ===========================================================================
# Asynchronous Engine & Session (FastAPI)
# ===========================================================================


def _build_async_engine() -> AsyncEngine:
    """
    Build and configure the asynchronous SQLAlchemy engine (asyncpg driver).

    The async engine is used exclusively by FastAPI route handlers. It uses
    AsyncAdaptedQueuePool (the default for async engines) with the same pool
    configuration as the sync engine.

    Returns:
        AsyncEngine: The configured async engine.
    """
    pool_cfg = settings.database.pool

    engine = create_async_engine(
        settings.get_async_db_url(),
        pool_size=pool_cfg.pool_size,
        max_overflow=pool_cfg.max_overflow,
        pool_timeout=pool_cfg.pool_timeout,
        pool_recycle=pool_cfg.pool_recycle,
        echo=pool_cfg.echo,
        pool_pre_ping=True,
        connect_args={
            "command_timeout": 30,
            "server_settings": {"application_name": "RDRS-async"},
        },
    )
    logger.debug(
        f"Async SQLAlchemy engine created | "
        f"host={settings.db_host}:{settings.db_port}/{settings.db_name}"
    )
    return engine


def get_async_engine() -> AsyncEngine:
    """
    Return the module-level async engine singleton, creating it on first call.

    Returns:
        AsyncEngine: The global async engine.
    """
    global _async_engine
    if _async_engine is None:
        _async_engine = _build_async_engine()
    return _async_engine


def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Return the async session factory, creating it on first call.

    Returns:
        async_sessionmaker[AsyncSession]: Factory for async database sessions.
    """
    global _AsyncSession
    if _AsyncSession is None:
        _AsyncSession = async_sessionmaker(
            bind=get_async_engine(),
            class_=AsyncSession,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _AsyncSession


@asynccontextmanager
async def get_async_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that provides a transactional async database session.

    Commits on success, rolls back on exception, always closes the session.

    Yields:
        AsyncSession: An active async database session.

    Raises:
        Exception: Re-raises any exception after performing rollback.

    Example:
        async with get_async_db_session() as session:
            result = await session.execute(select(ThreatScore))
            scores = result.scalars().all()
    """
    factory = get_async_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("Async DB session rolled back due to exception.")
            raise


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async database session per request.

    Designed for use with FastAPI's dependency injection system. The session
    is committed on clean exit and rolled back on exception.

    Yields:
        AsyncSession: An active database session for the request lifetime.

    Example:
        @router.get("/events")
        async def list_events(db: AsyncSession = Depends(get_async_session)):
            result = await db.execute(select(FileEvent))
            return result.scalars().all()
    """
    async with get_async_db_session() as session:
        yield session


# ===========================================================================
# Health Check
# ===========================================================================


async def check_db_connectivity() -> bool:
    """
    Verify that the database is reachable and accepting connections.

    Used by the FastAPI startup lifespan handler and the /health endpoint.

    Returns:
        bool: True if the database responded to a simple query; False otherwise.
    """
    try:
        async with get_async_db_session() as session:
            await session.execute(text("SELECT 1"))
        logger.info("Database connectivity check: OK")
        return True
    except Exception as exc:
        logger.error(f"Database connectivity check FAILED: {exc}")
        return False


def check_db_connectivity_sync() -> bool:
    """
    Synchronous version of the DB health check, used by init scripts and CLI.

    Returns:
        bool: True if database is reachable; False otherwise.
    """
    try:
        with get_db_session() as session:
            session.execute(text("SELECT 1"))
        logger.info("Database connectivity check (sync): OK")
        return True
    except Exception as exc:
        logger.error(f"Database connectivity check (sync) FAILED: {exc}")
        return False


# ===========================================================================
# Teardown
# ===========================================================================


async def dispose_async_engine() -> None:
    """
    Gracefully dispose of the async engine connection pool.

    Must be called during FastAPI shutdown lifespan to cleanly close all
    pooled connections before the process exits.
    """
    global _async_engine
    if _async_engine is not None:
        await _async_engine.dispose()
        _async_engine = None
        logger.info("Async database engine disposed.")


def dispose_sync_engine() -> None:
    """
    Gracefully dispose of the synchronous engine connection pool.

    Called during process shutdown or test teardown.
    """
    global _sync_engine
    if _sync_engine is not None:
        _sync_engine.dispose()
        _sync_engine = None
        logger.info("Sync database engine disposed.")
