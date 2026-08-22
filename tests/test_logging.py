"""
tests/test_logging.py
=====================
Unit tests for backend.core.logging redaction engine and audit trail.
"""

from pathlib import Path
from backend.core.logging import (
    _redact_message,
    audit_log,
)


def test_redact_sensitive_data_postgres_url() -> None:
    """PostgreSQL connection strings containing passwords must be redacted."""
    raw_log = "Connecting to postgresql://rdrs_user:SecretPassword123!@localhost:5432/rdrs_db"
    redacted = _redact_message(raw_log)
    assert "SecretPassword123!" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_sensitive_data_jwt_and_auth_headers() -> None:
    """Authorization headers and bearer tokens must be redacted."""
    raw_log = "Header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    redacted = _redact_message(raw_log)
    assert "eyJhbGci" not in redacted
    assert "[REDACTED]" in redacted


def test_audit_log_writes_to_file(sandbox: Path) -> None:
    """audit_log() must write structured entries without error."""
    audit_log(
        action="TEST_ACTION",
        details={"key": "value", "user": "admin"},
    )
