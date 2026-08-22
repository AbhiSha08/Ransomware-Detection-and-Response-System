"""
backend/api/routes/stream.py
=============================
Server-Sent Events (SSE) streaming endpoint for real-time dashboard updates.

This module implements a persistent SSE connection that pushes live Alert,
Incident, and ThreatScore records to connected frontend clients the instant
they are created — eliminating the need for client-side polling.

SSE Protocol:
    The response uses Content-Type: text/event-stream with the following
    event types emitted on the stream:

    ┌──────────────────────────────────────────────────────────────────┐
    │ event: connected                                                 │
    │ data: {"message": "RDRS SSE stream connected", ...}             │
    │                                                                  │
    │ event: score_update    (every score_interval seconds)            │
    │ data: {"score": 42.3, "severity": "MEDIUM", ...}                │
    │                                                                  │
    │ event: alert           (when a new Alert is created)             │
    │ data: {"id": "...", "alert_type": "...", "message": "...", ...}  │
    │                                                                  │
    │ event: incident        (when a new Incident is created)          │
    │ data: {"id": "...", "threat_score": 87.4, ...}                   │
    │                                                                  │
    │ event: heartbeat       (every 30 seconds, keep-alive)            │
    │ data: {"timestamp": "2026-08-13T..."}                            │
    └──────────────────────────────────────────────────────────────────┘

Architecture:
    - A module-level asyncio.Queue is the fan-out bus. The ResponseHandler
      and ScoringEngine push events here.
    - Each connected SSE client gets its own iterator that reads from a
      per-client asyncio.Queue (broadcast pattern).
    - A background broadcaster task reads from the central bus and fans
      out to all connected client queues.

Usage (frontend):
    const es = new EventSource("/api/v1/stream");
    es.addEventListener("alert", e => console.log(JSON.parse(e.data)));
    es.addEventListener("score_update", e => updateGauge(JSON.parse(e.data)));
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import StreamingResponse

from backend.api.dependencies import get_engine
from backend.core.logging import get_logger

_log = get_logger(__name__)
router = APIRouter(tags=["Real-Time Stream"])

# ---------------------------------------------------------------------------
# Central event bus — events published here are fanned out to all clients
# ---------------------------------------------------------------------------
_event_bus: asyncio.Queue[dict] = asyncio.Queue(maxsize=1024)

# ---------------------------------------------------------------------------
# Active client queues — one per connected SSE client
# ---------------------------------------------------------------------------
_client_queues: list[asyncio.Queue[dict]] = []

# ---------------------------------------------------------------------------
# Score broadcast interval (seconds)
# ---------------------------------------------------------------------------
_SCORE_BROADCAST_INTERVAL: float = 5.0

# ---------------------------------------------------------------------------
# Keep-alive heartbeat interval (seconds)
# ---------------------------------------------------------------------------
_HEARTBEAT_INTERVAL: float = 30.0


# ===========================================================================
# Public Publisher API (called by response handler and scoring engine)
# ===========================================================================


async def publish_alert(alert_data: dict) -> None:
    """
    Publish a new Alert event to all connected SSE clients.

    Called by ResponseHandler immediately after persisting an Alert record.

    Args:
        alert_data: Dict representation of the alert (use AlertOut.model_dump()).
    """
    await _publish({"event": "alert", "data": alert_data})


async def publish_incident(incident_data: dict) -> None:
    """
    Publish a new Incident event to all connected SSE clients.

    Called by ResponseHandler after persisting an Incident record.

    Args:
        incident_data: Dict representation of the incident.
    """
    await _publish({"event": "incident", "data": incident_data})


async def publish_file_event(event_data: dict) -> None:
    """
    Publish a new FileEvent to all connected SSE clients.
    """
    await _publish({"event": "file_event", "data": event_data})


async def publish_score_update(score: float, severity: str) -> None:
    """
    Publish a ThreatScore update to all connected SSE clients.

    Called by the scoring loop broadcaster task.

    Args:
        score:    Current threat score (0.0–100.0).
        severity: Current severity level string.
    """
    await _publish(
        {
            "event": "score_update",
            "data": {
                "score": score,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


async def _publish(event: dict) -> None:
    """
    Push an event onto the central bus. Non-blocking (drops if bus is full).

    Args:
        event: Event dict with ``event`` and ``data`` keys.
    """
    try:
        _event_bus.put_nowait(event)
    except asyncio.QueueFull:
        _log.warning("SSE event bus full — dropping event.")


# ===========================================================================
# SSE Formatting
# ===========================================================================


def _format_sse(event_type: str, data: dict, event_id: str | None = None) -> str:
    """
    Format a dict as an SSE message string conforming to the EventStream spec.

    Format:
        id: <uuid>\n
        event: <event_type>\n
        data: <json_string>\n
        \n

    Args:
        event_type: The SSE event name (e.g., "alert", "score_update").
        data:       The payload dict to JSON-serialize.
        event_id:   Optional event ID for client-side reconnect replay.

    Returns:
        str: Properly formatted SSE message string.
    """
    lines: list[str] = []
    if event_id:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event_type}")
    # Serialize each line of multi-line JSON as a separate `data:` line
    json_str = json.dumps(data, default=str)
    for line in json_str.splitlines():
        lines.append(f"data: {line}")
    lines.append("")  # Trailing blank line terminates the message
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Broadcaster Background Task
# ===========================================================================


async def _broadcaster() -> None:
    """
    Background task that reads from the central event bus and fans out to
    all connected client queues.

    Runs as a singleton asyncio task started during app startup.
    Also injects periodic score_update and heartbeat events.
    """
    _log.info("SSE broadcaster started.")
    score_tick = 0.0
    heartbeat_tick = 0.0

    while True:
        try:
            # Check for new events (non-blocking)
            try:
                event = _event_bus.get_nowait()
                for client_q in list(_client_queues):
                    try:
                        client_q.put_nowait(event)
                    except asyncio.QueueFull:
                        pass
                _event_bus.task_done()
            except asyncio.QueueEmpty:
                pass

            await asyncio.sleep(0.1)  # 100ms tick
            score_tick += 0.1
            heartbeat_tick += 0.1

            # Periodic score broadcast
            if score_tick >= _SCORE_BROADCAST_INTERVAL:
                score_tick = 0.0
                try:
                    engine = get_engine()
                    score: float = getattr(engine, "current_score", 0.0)
                    severity: str = getattr(engine, "current_severity", "NOMINAL")
                    score_event = {
                        "event": "score_update",
                        "data": {
                            "score": score,
                            "severity": severity,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    }
                    for client_q in list(_client_queues):
                        try:
                            client_q.put_nowait(score_event)
                        except asyncio.QueueFull:
                            pass
                except RuntimeError:
                    pass  # Engine not yet initialized

            # Periodic heartbeat
            if heartbeat_tick >= _HEARTBEAT_INTERVAL:
                heartbeat_tick = 0.0
                hb_event = {
                    "event": "heartbeat",
                    "data": {"timestamp": datetime.now(timezone.utc).isoformat()},
                }
                for client_q in list(_client_queues):
                    try:
                        client_q.put_nowait(hb_event)
                    except asyncio.QueueFull:
                        pass

        except asyncio.CancelledError:
            _log.info("SSE broadcaster stopped.")
            break
        except Exception as exc:
            _log.error(f"SSE broadcaster error: {exc}")
            await asyncio.sleep(1.0)


# Store broadcaster task reference for lifecycle management
_broadcaster_task: asyncio.Task | None = None


def start_broadcaster() -> None:
    """Start the SSE broadcaster background task. Called during app startup."""
    global _broadcaster_task
    if _broadcaster_task is None or _broadcaster_task.done():
        _broadcaster_task = asyncio.create_task(
            _broadcaster(), name="rdrs-sse-broadcaster"
        )
        _log.info("SSE broadcaster task created.")


async def stop_broadcaster() -> None:
    """Stop the SSE broadcaster task gracefully. Called during app shutdown."""
    global _broadcaster_task
    if _broadcaster_task and not _broadcaster_task.done():
        _broadcaster_task.cancel()
        try:
            await _broadcaster_task
        except asyncio.CancelledError:
            pass
        _broadcaster_task = None


# ===========================================================================
# SSE Generator (per-client)
# ===========================================================================


async def _sse_generator(
    client_queue: asyncio.Queue[dict],
    request: Request,
) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted strings for a single client.

    Runs until the client disconnects (request.is_disconnected() becomes True).

    Args:
        client_queue: Per-client event queue populated by the broadcaster.
        request:      Starlette request used to detect client disconnection.

    Yields:
        str: SSE-formatted event strings.
    """
    # Send connection confirmation
    yield _format_sse(
        "connected",
        {
            "message": "RDRS SSE stream connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stream_version": "1.0",
        },
        event_id=str(uuid.uuid4()),
    )

    while True:
        if await request.is_disconnected():
            _log.debug("SSE client disconnected.")
            break

        try:
            event = await asyncio.wait_for(client_queue.get(), timeout=1.0)
            yield _format_sse(
                event_type=event["event"],
                data=event["data"],
                event_id=str(uuid.uuid4()),
            )
            client_queue.task_done()
        except asyncio.TimeoutError:
            # No event in 1s — loop back to check for disconnect
            continue
        except asyncio.CancelledError:
            break
        except Exception as exc:
            _log.error(f"SSE generator error: {exc}")
            break


# ===========================================================================
# SSE Route Handler
# ===========================================================================


@router.get(
    "/stream",
    summary="Real-time SSE event stream",
    description=(
        "Opens a persistent Server-Sent Events connection. The server pushes "
        "the following event types:\n\n"
        "- **connected** — Confirmation on connection.\n"
        "- **score_update** — Current threat score every 5 seconds.\n"
        "- **alert** — Pushed immediately when a new Alert is created.\n"
        "- **incident** — Pushed immediately when a new Incident is declared.\n"
        "- **heartbeat** — Keep-alive pulse every 30 seconds.\n\n"
        "Use the browser's native `EventSource` API or an SSE client library to connect.\n\n"
        "**Frontend usage:**\n"
        "```javascript\n"
        "const es = new EventSource('/api/v1/stream');\n"
        "es.addEventListener('alert', e => console.log(JSON.parse(e.data)));\n"
        "```"
    ),
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream (persistent connection)",
        }
    },
)
async def sse_stream(request: Request) -> StreamingResponse:
    """
    Establish a Server-Sent Events stream for real-time dashboard updates.

    Each client gets an isolated asyncio.Queue registered with the broadcaster.
    On disconnect, the queue is removed from the broadcast list.

    Args:
        request: The incoming HTTP request (used to detect client disconnect).

    Returns:
        StreamingResponse: Persistent SSE stream with text/event-stream content type.
    """
    # Create per-client queue and register with broadcaster
    client_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=256)
    _client_queues.append(client_queue)

    client_ip = request.client.host if request.client else "unknown"
    _log.info(f"New SSE client connected | ip={client_ip} | total={len(_client_queues)}")

    async def cleanup_generator() -> AsyncGenerator[str, None]:
        """Wrapper generator that ensures client queue is cleaned up on disconnect."""
        try:
            async for chunk in _sse_generator(client_queue, request):
                yield chunk
        finally:
            if client_queue in _client_queues:
                _client_queues.remove(client_queue)
            _log.info(
                f"SSE client removed | ip={client_ip} | "
                f"remaining={len(_client_queues)}"
            )

    return StreamingResponse(
        cleanup_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",      # Disable nginx buffering
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
    )
