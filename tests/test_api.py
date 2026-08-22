"""
tests/test_api.py
==================
Unit & integration tests for FastAPI REST API routes.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.main import app
from backend.api.dependencies import get_db


@pytest.mark.asyncio
async def test_health_endpoint(async_session: AsyncSession) -> None:
    """GET /api/v1/health returns HTTP 200 with health status JSON."""
    app.dependency_overrides[get_db] = lambda: async_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert data["database_reachable"] is True

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_status_endpoint() -> None:
    """GET /api/v1/status returns system status and scoring config."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert "current_score" in data
        assert "severity" in data
        assert "scoring_config" in data


@pytest.mark.asyncio
async def test_list_events_endpoint(async_session: AsyncSession) -> None:
    """GET /api/v1/events returns paginated event list."""
    app.dependency_overrides[get_db] = lambda: async_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/events?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "items" in data

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_list_alerts_endpoint(async_session: AsyncSession) -> None:
    """GET /api/v1/alerts returns paginated alert list."""
    app.dependency_overrides[get_db] = lambda: async_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/alerts?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "items" in data

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_settings_endpoint_blocks_active_mode() -> None:
    """POST /api/v1/settings with mode='active' must return HTTP 403 Forbidden."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/settings",
            json={"response_mode": "active"},
        )
        assert response.status_code == 403
        assert "active" in response.json()["detail"].lower()
