"""
backend/core/logging.py
=======================
Centralized, production-grade logging engine for the RDRS application.

This module configures Loguru with five distinct log sinks:
  1. **STDERR (console)**  — Human-readable colorized output during development.
  2. **logs/rdrs.log**     — Full application log at configured level (rotating).
  3. **logs/events.log**   — File-system and process events only (INFO+).
  4. **logs/alerts.log**   — Alert and threat score records (WARNING+).
  5. **logs/errors.log**   — Errors and critical failures only (ERROR+).
  6. **logs/audit.log**    — Append-only, tamper-evident audit trail (never rotated).

Security Features:
  - A **redaction filter** automatically strips database passwords, connection
    strings, JWTs, and authorization headers from ALL log records before they
    are written to any sink.
  - The audit log sink has NO rotation or compression — entries are permanent.
  - Diagnose mode (full variable inspection in tracebacks) is disabled in production.

Usage:
    from backend.core.logging import get_logger

    logger = get_logger(__name__)
    logger.info("Monitoring started", watch_path="/home/user/docs")
    logger.bind(event_type="FILE_RENAME").warning("Suspicious rename detected")
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Message, Record

# ---------------------------------------------------------------------------
# Project root resolution
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
LOGS_DIR: Path = PROJECT_ROOT / "logs"

# ---------------------------------------------------------------------------
# Sensitive data patterns for redaction
# ---------------------------------------------------------------------------
# These patterns are applied to the fully formatted log message string.
# Order matters: more-specific patterns should come first.
_REDACTION_RULES: list[tuple[re.Pattern[str], str]] = [
    # PostgreSQL / SQLAlchemy connection strings (sync + async drivers)
    (
        re.compile(
            r"(postgresql(?:\+psycopg2|\+asyncpg)?://[^:]+:)([^@]+)(@)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]\3",
    ),
    # Authorization: Bearer <token>
    (
        re.compile(r"(Authorization:\s*Bearer\s+)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # JWT tokens (three base64url segments separated by dots)
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        "[JWT_REDACTED]",
    ),
    # password= query parameters or keyword arguments
    (
        re.compile(r"(password\s*[=:]\s*)['\"]?[^\s'\",}]+['\"]?", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # RDRS_DB_PASSWORD env var values
    (
        re.compile(r"(RDRS_DB_PASSWORD\s*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # RDRS_JWT_SECRET env var values
    (
        re.compile(r"(RDRS_JWT_SECRET\s*[=:]\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # Generic secret= patterns
    (
        re.compile(r"(secret\s*[=:]\s*)['\"]?\S+['\"]?", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # X-API-Key headers
    (
        re.compile(r"(X-API-Key:\s*)\S+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
]


def _redact_message(message: str) -> str:
    """
    Apply all redaction rules to a log message string.

    Args:
        message: The raw formatted log message.

    Returns:
        The message with all sensitive patterns replaced by [REDACTED].
    """
    for pattern, replacement in _REDACTION_RULES:
        message = pattern.sub(replacement, message)
    return message


# ---------------------------------------------------------------------------
# Loguru filter functions
# ---------------------------------------------------------------------------


def _redaction_filter(record: "Record") -> bool:
    """
    Loguru filter that mutates the record message in-place to redact
    sensitive data before the record is serialized to any sink.

    This filter is attached to every sink so that NO sink ever receives
    unredacted sensitive content.

    Args:
        record: The Loguru log record dict.

    Returns:
        True always (this filter never suppresses records, only redacts them).
    """
    record["message"] = _redact_message(record["message"])
    # Also redact any extra fields that might contain sensitive data
    if "extra" in record and isinstance(record["extra"], dict):
        for key, value in record["extra"].items():
            if isinstance(value, str):
                record["extra"][key] = _redact_message(value)
    return True


def _events_filter(record: "Record") -> bool:
    """
    Filter for the events sink: passes records that carry an `event_type`
    extra field, or have level >= INFO.

    Args:
        record: The Loguru log record dict.

    Returns:
        True if the record should be written to the events log.
    """
    return bool(record["extra"].get("event_type")) or record["level"].no >= 20  # INFO


def _alerts_filter(record: "Record") -> bool:
    """
    Filter for the alerts sink: passes records with level >= WARNING or
    those explicitly tagged with `alert=True` in their extra context.

    Args:
        record: The Loguru log record dict.

    Returns:
        True if the record should be written to the alerts log.
    """
    return record["extra"].get("alert", False) or record["level"].no >= 30  # WARNING


def _errors_filter(record: "Record") -> bool:
    """
    Filter for the errors sink: passes only ERROR and CRITICAL records.

    Args:
        record: The Loguru log record dict.

    Returns:
        True for ERROR or CRITICAL level records.
    """
    return record["level"].no >= 40  # ERROR


def _audit_filter(record: "Record") -> bool:
    """
    Filter for the audit sink: passes only records explicitly tagged with
    `audit=True` in their extra context. These are append-only, permanent records.

    Args:
        record: The Loguru log record dict.

    Returns:
        True if record["extra"]["audit"] is truthy.
    """
    return bool(record["extra"].get("audit", False))


# ---------------------------------------------------------------------------
# JSON formatter  (REFERENCE ONLY — NOT used as format= argument)
# ---------------------------------------------------------------------------
# !! IMPORTANT — DO NOT pass _json_formatter as format= to logger.add() !!
#
# Root cause of KeyError: '"timestamp"':
#   Loguru internally calls  str.format_map(record)  on the *string returned*
#   by any callable passed as  format= .  This means after _json_formatter
#   returns  '{"timestamp": "2026-..."}'  Loguru does:
#
#       '{"timestamp": "2026-..."}'.format_map(record)
#
#   Python's str.format_map then treats {timestamp, {time, {level, etc. inside
#   the JSON body as template variables and raises KeyError for any key it
#   cannot find in the record mapping.
#
# Fix: Use  serialize=True  on all file sinks.  When serialize=True is set,
#   Loguru uses its own internal JSON serializer and completely bypasses the
#   str.format_map pipeline — no double-interpolation, no KeyError.
#   The console sink is unaffected because it uses the plain _TEXT_FORMAT
#   string (which contains only valid Loguru {field} tokens, not JSON braces).
# ---------------------------------------------------------------------------


def _json_formatter(record: "Record") -> str:  # pragma: no cover
    """
    Reference-only JSON serializer.  NOT wired to any logger.add() call.

    Retained for unit-testing and offline SIEM tooling that may import and
    call this function directly on a record dict.

    Output schema::

        {
            "timestamp": "ISO8601",
            "level": "INFO",
            "logger": "module.name",
            "message": "...",
            "extra": {...},
            "exception": {"type": "...", "value": "..."} | null
        }

    Args:
        record: The Loguru log record dict.

    Returns:
        A JSON-serialized string terminated with a newline.
    """
    log_entry: dict[str, object] = {
        "timestamp": record["time"].isoformat(),
        "level": record["level"].name,
        "logger": record["name"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
        "extra": record["extra"],
    }
    if record["exception"]:
        exc = record["exception"]
        log_entry["exception"] = {
            "type": exc.type.__name__ if exc.type else None,
            "value": str(exc.value) if exc.value else None,
        }
    return json.dumps(log_entry, default=str) + "\n"


# ---------------------------------------------------------------------------
# Text format string (console + text-mode file sinks)
# ---------------------------------------------------------------------------
_TEXT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
    "<level>{message}</level>"
    "{exception}"
)


# ---------------------------------------------------------------------------
# Public initializer
# ---------------------------------------------------------------------------


def setup_logging(
    *,
    level: str = "DEBUG",
    log_format: str = "json",
    rotation_size: str = "50 MB",
    retention: str = "30 days",
    compression: str = "gz",
    diagnose: bool = True,
    backtrace: bool = True,
) -> None:
    """
    Configure all Loguru sinks for the RDRS application.

    This function should be called ONCE at application startup (e.g., in the
    FastAPI lifespan handler or the CLI entry point). Calling it multiple times
    is safe — it removes all existing handlers before re-configuring.

    Args:
        level:          Minimum log level for the application and file sinks.
        log_format:     "json" for structured SIEM-ready output, "text" for human-readable.
        rotation_size:  Loguru rotation size string (e.g., "50 MB").
        retention:      Log retention period string (e.g., "30 days").
        compression:    Compression format for rotated logs (e.g., "gz").
        diagnose:       Enable variable inspection in tracebacks (disable in production).
        backtrace:      Enable full stack tracebacks on exceptions.

    Implementation note — why serialize=True instead of format=_json_formatter:
        Loguru internally calls ``str.format_map(record)`` on the *string*
        returned by a callable ``format=`` argument.  Because _json_formatter
        returns a JSON string whose keys contain curly braces (e.g.
        ``{"timestamp": "..."}``), Python's str.format_map misinterprets
        those braces as template variables and raises::

            KeyError: '"timestamp"'

        Using ``serialize=True`` bypasses this pipeline entirely — Loguru
        serializes the record itself using its own encoder, which never
        passes the result back through str.format_map.
    """
    # Ensure logs directory exists
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Remove all default handlers
    logger.remove()

    # Determine whether file sinks should use Loguru's native JSON serializer.
    # When serialize=True, Loguru skips the format= string pipeline entirely,
    # preventing the KeyError: '"timestamp"' caused by format_map re-expansion.
    is_json = log_format == "json"

    # Shared kwargs for rotating file sinks
    # NOTE: format= is intentionally NOT included here — it is set per-sink
    # below so that JSON sinks can use serialize=True without a format= string.
    _rotating_kwargs: dict[str, object] = {
        "rotation": rotation_size,
        "retention": retention,
        "compression": compression,
        "encoding": "utf-8",
        "enqueue": True,       # Non-blocking async write via background thread
        "backtrace": backtrace,
        "diagnose": diagnose,
        "filter": _redaction_filter,
    }

    # ------------------------------------------------------------------
    # Sink 1: Console (STDERR) — always text format, colorized
    # The _TEXT_FORMAT string uses only valid Loguru {field} tokens
    # (not JSON braces), so it is safe to pass as format= here.
    # ------------------------------------------------------------------
    logger.add(
        sys.stderr,
        level=level,
        format=_TEXT_FORMAT,
        colorize=True,
        backtrace=backtrace,
        diagnose=diagnose,
        filter=_redaction_filter,
        enqueue=True,
    )

    # ------------------------------------------------------------------
    # Sink 2: Application log — all records at configured level
    # FIX: serialize=True replaces format=_json_formatter to avoid
    #      KeyError raised by Loguru's internal str.format_map pass.
    # ------------------------------------------------------------------
    logger.add(
        str(LOGS_DIR / "rdrs.log"),
        level=level,
        serialize=is_json,
        format=_TEXT_FORMAT if not is_json else "{message}",
        **_rotating_kwargs,  # type: ignore[arg-type]
    )

    # ------------------------------------------------------------------
    # Sink 3: Events log — filesystem + process events
    # FIX: serialize=True replaces format=_json_formatter.
    # ------------------------------------------------------------------
    logger.add(
        str(LOGS_DIR / "events.log"),
        level="INFO",
        serialize=is_json,
        format=_TEXT_FORMAT if not is_json else "{message}",
        filter=lambda r: _redaction_filter(r) and _events_filter(r),
        rotation=rotation_size,
        retention=retention,
        compression=compression,
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

    # ------------------------------------------------------------------
    # Sink 4: Alerts log — WARNING and above, or tagged alert=True
    # FIX: serialize=True replaces format=_json_formatter.
    # ------------------------------------------------------------------
    logger.add(
        str(LOGS_DIR / "alerts.log"),
        level="WARNING",
        serialize=is_json,
        format=_TEXT_FORMAT if not is_json else "{message}",
        filter=lambda r: _redaction_filter(r) and _alerts_filter(r),
        rotation=rotation_size,
        retention=retention,
        compression=compression,
        encoding="utf-8",
        enqueue=True,
        backtrace=backtrace,
        diagnose=False,   # Never expose variable values in alert logs
    )

    # ------------------------------------------------------------------
    # Sink 5: Errors log — ERROR and CRITICAL only
    # FIX: serialize=True replaces format=_json_formatter.
    # ------------------------------------------------------------------
    logger.add(
        str(LOGS_DIR / "errors.log"),
        level="ERROR",
        serialize=is_json,
        format=_TEXT_FORMAT if not is_json else "{message}",
        filter=lambda r: _redaction_filter(r) and _errors_filter(r),
        rotation=rotation_size,
        retention=retention,
        compression=compression,
        encoding="utf-8",
        enqueue=True,
        backtrace=backtrace,
        diagnose=False,
    )

    # ------------------------------------------------------------------
    # Sink 6: Audit log — append-only, NO rotation, tamper-evident trail
    # FIX: serialize=True replaces format=_json_formatter.
    # ------------------------------------------------------------------
    logger.add(
        str(LOGS_DIR / "audit.log"),
        level="INFO",
        serialize=is_json,
        format=_TEXT_FORMAT if not is_json else "{message}",
        filter=lambda r: _redaction_filter(r) and _audit_filter(r),
        rotation=None,      # Never rotate — audit logs must not be truncated
        retention=None,
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
        mode="a",           # Strict append mode
    )

    logger.success(
        "RDRS logging subsystem initialized | "
        f"level={level} | format={log_format} | sinks=6"
    )


def get_logger(name: str) -> "logger.__class__":
    """
    Return a contextualized Loguru logger bound with the given module name.

    This is the preferred way to obtain a logger in any RDRS module.

    Args:
        name: Usually `__name__` of the calling module.

    Returns:
        A Loguru logger instance pre-bound with the module name.

    Example:
        logger = get_logger(__name__)
        logger.info("Watcher started.")
    """
    return logger.bind(module=name)


# ---------------------------------------------------------------------------
# Convenience audit logger
# ---------------------------------------------------------------------------


def audit_log(action: str, details: dict[str, object]) -> None:
    """
    Write a structured audit entry to the audit log sink.

    All responses, alerts, and operator actions must call this function to
    maintain the tamper-evident audit trail required for SOC compliance.

    Args:
        action:  A short action identifier (e.g., "ALERT_DISMISSED", "REPORT_GENERATED").
        details: Arbitrary key-value pairs describing the event context.

    Example:
        audit_log("ALERT_DISMISSED", {"alert_id": 42, "operator": "soc_user_1"})
    """
    logger.bind(audit=True, audit_action=action, **details).info(
        f"AUDIT | {action} | {details}"
    )


# ---------------------------------------------------------------------------
# Intercept stdlib logging (third-party libraries)
# ---------------------------------------------------------------------------
import logging  # noqa: E402 — must come after loguru setup


class _InterceptHandler(logging.Handler):
    """
    Redirect Python stdlib `logging` records into Loguru.

    Third-party libraries (SQLAlchemy, uvicorn, watchdog) use stdlib logging.
    This handler ensures their output is subject to the same redaction filters
    and sink routing as native RDRS logs.
    """

    def emit(self, record: logging.LogRecord) -> None:
        """Translate and forward a stdlib LogRecord to Loguru."""
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = str(record.levelno)

        frame, depth = sys._getframe(6), 6  # noqa: SLF001
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back  # type: ignore[assignment]
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def intercept_stdlib_logging(
    libraries: list[str] | None = None,
    level: int = logging.DEBUG,
) -> None:
    """
    Install the Loguru intercept handler for stdlib logging.

    Args:
        libraries: List of library logger names to intercept.
                   If None, intercepts the root logger (catches everything).
        level:     Minimum stdlib level to forward to Loguru.

    Example:
        intercept_stdlib_logging(["sqlalchemy", "uvicorn", "watchdog"])
    """
    handler = _InterceptHandler()
    if libraries:
        for lib in libraries:
            lib_logger = logging.getLogger(lib)
            lib_logger.handlers = [handler]
            lib_logger.propagate = False
            lib_logger.setLevel(level)
    else:
        logging.basicConfig(handlers=[handler], level=level, force=True)
