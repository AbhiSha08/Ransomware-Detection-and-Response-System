"""
RDRS Test Suite — Root Configuration (conftest.py)
====================================================
This conftest.py enforces the sandbox containment policy defined in
PROJECT_RULES.md §3.1. All filesystem I/O during tests MUST occur within
the configured sandbox directory or pytest's tmp_path fixture.

Rules enforced here:
  - The RDRS_SANDBOX_ROOT fixture always resolves to data/sandbox/.
  - The sandbox directory is created fresh before each test session.
  - All sandbox contents are wiped after each test session (auto-clean).
  - RDRS_TEST_MODE=true is set globally so SQLAlchemy uses NullPool/StaticPool.
  - Shared in-memory SQLite engine with StaticPool connects all background calls.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Set RDRS_TEST_MODE=true before importing RDRS modules
os.environ["RDRS_TEST_MODE"] = "true"

from backend.database.models import Base
import backend.database.session as db_session_module

# =============================================================================
# Constants
# =============================================================================

PROJECT_ROOT: Path = Path(__file__).parent.parent.resolve()
SANDBOX_ROOT: Path = PROJECT_ROOT / "data" / "sandbox"


# =============================================================================
# Session-Scoped Fixtures
# =============================================================================


@pytest.fixture(scope="session", autouse=True)
def enforce_sandbox_root() -> None:
    """
    Session fixture that validates the sandbox directory exists and is
    isolated from the real filesystem.
    """
    try:
        SANDBOX_ROOT.resolve().relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError(
            f"SECURITY: Sandbox path '{SANDBOX_ROOT}' is outside the project "
            f"root '{PROJECT_ROOT}'. Test suite aborted."
        ) from exc

    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session", autouse=True)
def cleanup_sandbox_after_session(enforce_sandbox_root: None) -> None:
    """
    Session fixture that cleans up sandbox artifacts after the test session.
    """
    yield

    auto_clean = os.environ.get("RDRS_TEST_AUTO_CLEAN", "true").lower() == "true"
    if auto_clean and SANDBOX_ROOT.exists():
        shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Database Fixtures (Async SQLite StaticPool testing)
# =============================================================================

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function", autouse=True)
async def async_session(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[AsyncSession, None]:
    """
    Provides a clean, isolated async database session backed by an in-memory
    SQLite database with StaticPool for each test function.
    Creates all tables before yielding and wires backend.database.session singletons.
    """
    engine = create_async_engine(
        TEST_DB_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    # Monkeypatch backend.database.session singletons to use test engine
    monkeypatch.setattr(db_session_module, "_async_engine", engine)
    monkeypatch.setattr(db_session_module, "_AsyncSession", session_factory)

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


# =============================================================================
# Function-Scoped Sandbox Fixtures
# =============================================================================


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    """
    Provides a clean, isolated temporary directory within the sandbox for each test.
    """
    test_sandbox = SANDBOX_ROOT / tmp_path.name
    test_sandbox.mkdir(parents=True, exist_ok=True)
    return test_sandbox


@pytest.fixture()
def sandbox_file(sandbox: Path) -> Path:
    """
    Provides a pre-created dummy file within the sandbox for testing.
    """
    dummy_file = sandbox / "dummy_document.docx"
    dummy_file.write_bytes(b"X" * 1024)
    return dummy_file


def assert_in_sandbox(path: Path) -> None:
    """
    Assert that a given path is strictly within the sandbox boundary.
    """
    try:
        path.resolve().relative_to(SANDBOX_ROOT.resolve())
    except ValueError:
        raise AssertionError(
            f"POLICY VIOLATION: Path '{path}' is outside the sandbox "
            f"root '{SANDBOX_ROOT}'. See PROJECT_RULES.md §3.1."
        )
