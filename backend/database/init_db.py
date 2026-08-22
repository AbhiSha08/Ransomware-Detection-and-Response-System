"""
backend/database/init_db.py
===========================
Database initialization and schema management for the RDRS application.

This module handles:
  1. Automatic creation of all ORM-defined tables via `Base.metadata.create_all()`.
  2. Extension setup (e.g., enabling `pgcrypto` for `gen_random_uuid()`).
  3. Startup connectivity verification before attempting table creation.
  4. Idempotent operation: safe to run multiple times (uses `checkfirst=True`).
  5. CLI entry point: `python -m backend.database.init_db` for manual initialization.

Alembic Notice:
  This initializer creates tables directly using SQLAlchemy metadata. It is
  intended ONLY for initial development setup and CI/CD pipeline bootstrapping.
  All subsequent schema changes MUST be managed as Alembic migrations.
  See PROJECT_RULES.md §3.4 for the Alembic migration workflow.

Usage:
    # Programmatic (called from FastAPI startup or a setup script):
    from backend.database.init_db import initialize_database
    initialize_database()

    # CLI:
    python -m backend.database.init_db
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from loguru import logger
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError, ProgrammingError

# Ensure project root is on sys.path when run as __main__
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.core.config import settings  # noqa: E402
from backend.core.logging import setup_logging  # noqa: E402
from backend.database.models import Base  # noqa: E402  — imports all models
from backend.database.session import (  # noqa: E402
    check_db_connectivity_sync,
    dispose_sync_engine,
    get_db_session,
    get_sync_engine,
)

# ---------------------------------------------------------------------------
# PostgreSQL extensions required by RDRS
# ---------------------------------------------------------------------------
_REQUIRED_EXTENSIONS: list[str] = [
    "pgcrypto",   # Provides gen_random_uuid() used in server_default
    "pg_stat_statements",  # Query performance monitoring (optional but recommended)
]

# ---------------------------------------------------------------------------
# Expected table names (used for post-init verification)
# ---------------------------------------------------------------------------
_EXPECTED_TABLES: list[str] = [
    "file_events",
    "process_snapshots",
    "threat_scores",
    "alerts",
    "incidents",
]


# ===========================================================================
# Extension Setup
# ===========================================================================


def _ensure_extensions(*, ignore_errors: bool = True) -> None:
    """
    Ensure required PostgreSQL extensions are installed in the target database.

    Attempts to install each extension listed in `_REQUIRED_EXTENSIONS` using
    `CREATE EXTENSION IF NOT EXISTS`. If an extension is unavailable (e.g.,
    the server package is not installed) and `ignore_errors=False`, the error
    is re-raised.

    Args:
        ignore_errors: If True, log and skip extensions that fail to install
                       rather than halting initialization. Defaults to True.
    """
    engine = get_sync_engine()
    
    # Strict whitelist to prevent SQL injection via string interpolation
    _ALLOWED_EXTENSIONS = {"pgcrypto", "pg_stat_statements"}
    
    with engine.connect() as conn:
        for ext in _REQUIRED_EXTENSIONS:
            if ext not in _ALLOWED_EXTENSIONS:
                logger.error(f"Refusing to install unapproved extension: {ext}")
                continue
                
            try:
                conn.execute(text(f"CREATE EXTENSION IF NOT EXISTS {ext}"))
                conn.commit()
                logger.debug(f"PostgreSQL extension ensured: {ext}")
            except (ProgrammingError, OperationalError) as exc:
                if ignore_errors:
                    logger.warning(
                        f"Could not install extension '{ext}' (may require superuser): {exc}. "
                        f"Skipping — server_default UUID generation will fall back to app-layer."
                    )
                else:
                    raise


# ===========================================================================
# Table Creation
# ===========================================================================


def _create_tables() -> None:
    """
    Create all ORM-defined tables using SQLAlchemy metadata.

    This is idempotent: tables that already exist are not recreated or
    truncated (`checkfirst=True` is implicit in `create_all`).

    Raises:
        OperationalError: If the database connection fails during DDL execution.
    """
    engine = get_sync_engine()
    logger.info("Creating RDRS database tables (if not exist)...")
    Base.metadata.create_all(bind=engine, checkfirst=True)
    logger.success("Database tables created/verified successfully.")


# ===========================================================================
# Post-Init Verification
# ===========================================================================


def _verify_tables() -> bool:
    """
    Verify that all expected tables exist in the database after initialization.

    Returns:
        bool: True if all expected tables are present; False if any are missing.
    """
    engine = get_sync_engine()
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    missing = [t for t in _EXPECTED_TABLES if t not in existing_tables]

    if missing:
        logger.error(f"Post-init verification FAILED. Missing tables: {missing}")
        return False

    logger.success(
        f"Post-init verification PASSED. All {len(_EXPECTED_TABLES)} tables present: "
        f"{_EXPECTED_TABLES}"
    )
    return True


# ===========================================================================
# Connectivity Wait Loop
# ===========================================================================


def _wait_for_db(
    *,
    max_retries: int = 10,
    retry_delay_seconds: float = 3.0,
) -> None:
    """
    Block until the database is reachable, retrying with linear backoff.

    This is used during container startup where the application may start
    before the PostgreSQL container has finished initializing.

    Args:
        max_retries:          Maximum number of connection attempts before giving up.
        retry_delay_seconds:  Seconds to wait between retries.

    Raises:
        RuntimeError: If the database is not reachable after `max_retries` attempts.
    """
    logger.info(
        f"Waiting for database at {settings.db_host}:{settings.db_port}..."
    )
    for attempt in range(1, max_retries + 1):
        if check_db_connectivity_sync():
            logger.info(f"Database reachable on attempt {attempt}/{max_retries}.")
            return
        if attempt < max_retries:
            logger.warning(
                f"Database not ready (attempt {attempt}/{max_retries}). "
                f"Retrying in {retry_delay_seconds}s..."
            )
            time.sleep(retry_delay_seconds)

    raise RuntimeError(
        f"Database at {settings.db_host}:{settings.db_port}/{settings.db_name} "
        f"did not become reachable after {max_retries} attempts. "
        f"Ensure the PostgreSQL container is running: `docker compose up -d rdrs_db`"
    )


# ===========================================================================
# Public Entry Point
# ===========================================================================


def initialize_database(
    *,
    wait_for_db: bool = True,
    max_retries: int = 10,
    retry_delay: float = 3.0,
    install_extensions: bool = True,
) -> bool:
    """
    Initialize the RDRS database schema.

    Performs the following steps in order:
      1. Wait for the database to become reachable (optional).
      2. Install required PostgreSQL extensions (optional, non-fatal on failure).
      3. Create all ORM-defined tables (idempotent).
      4. Verify all expected tables are present.

    This function is safe to call on every application startup. If the database
    is already fully initialized, it will complete in milliseconds.

    Args:
        wait_for_db:        If True, poll the DB until reachable before proceeding.
        max_retries:        Max connection attempts if wait_for_db is True.
        retry_delay:        Seconds between retry attempts.
        install_extensions: If True, attempt to install PostgreSQL extensions.

    Returns:
        bool: True if initialization succeeded; False if verification failed.

    Raises:
        RuntimeError: If wait_for_db=True and the DB is unreachable after max_retries.
    """
    logger.info(
        f"=== RDRS Database Initialization | "
        f"db={settings.db_name}@{settings.db_host}:{settings.db_port} ==="
    )

    # Step 1: Wait for database
    if wait_for_db:
        _wait_for_db(max_retries=max_retries, retry_delay_seconds=retry_delay)

    # Step 2: Install extensions
    if install_extensions:
        _ensure_extensions(ignore_errors=True)

    # Step 3: Create tables
    _create_tables()

    # Step 4: Verify
    success = _verify_tables()

    if success:
        logger.success("RDRS database initialization complete.")
    else:
        logger.critical(
            "RDRS database initialization FAILED. Some tables are missing. "
            "Check logs for DDL errors."
        )

    return success


def drop_all_tables(*, confirm: bool = False) -> None:
    """
    Drop ALL RDRS tables from the database.

    DANGER: This is a destructive, irreversible operation. Used only for
    development teardown and test environment resets.

    Args:
        confirm: Must be explicitly set to True to prevent accidental calls.

    Raises:
        ValueError: If `confirm` is not True.
        RuntimeError: If called when environment is 'production'.
    """
    if settings.is_production():
        raise RuntimeError(
            "drop_all_tables() is FORBIDDEN in production environments. "
            "Use Alembic downgrade migrations instead."
        )
    if not confirm:
        raise ValueError(
            "drop_all_tables() requires confirm=True to prevent accidents."
        )

    engine = get_sync_engine()
    logger.warning("!!! Dropping ALL RDRS tables from database !!!")
    Base.metadata.drop_all(bind=engine)
    logger.warning("All tables dropped.")


# ===========================================================================
# CLI Entry Point
# ===========================================================================

if __name__ == "__main__":
    import argparse

    # Initialize logging for standalone CLI usage
    setup_logging(
        level=settings.logging.level,
        log_format=settings.logging.format,
        rotation_size=settings.logging.rotation.size,
        retention=settings.logging.rotation.retention,
        compression=settings.logging.rotation.compression,
        diagnose=settings.logging.diagnose,
        backtrace=settings.logging.backtrace,
    )

    parser = argparse.ArgumentParser(
        description="RDRS Database Initialization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m backend.database.init_db               # Initialize database
  python -m backend.database.init_db --no-wait     # Skip DB wait loop
  python -m backend.database.init_db --verify-only # Only verify tables exist
        """,
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for the database to become reachable.",
    )
    parser.add_argument(
        "--no-extensions",
        action="store_true",
        help="Skip PostgreSQL extension installation.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify that tables exist; do not create anything.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=10,
        help="Maximum DB connection retries (default: 10).",
    )
    args = parser.parse_args()

    if args.verify_only:
        ok = _verify_tables()
    else:
        ok = initialize_database(
            wait_for_db=not args.no_wait,
            max_retries=args.max_retries,
            install_extensions=not args.no_extensions,
        )

    dispose_sync_engine()
    sys.exit(0 if ok else 1)
