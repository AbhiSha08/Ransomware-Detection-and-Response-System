"""
backend/api/schemas.py
=======================
Pydantic v2 request and response schemas for all RDRS API endpoints.

All schemas use ``model_config = ConfigDict(from_attributes=True)`` so they
can be directly instantiated from SQLAlchemy ORM objects via
``Model.model_validate(orm_obj)``.

Schema Naming Convention:
    - ``<Entity>Out``     — Response payload returned to the client.
    - ``<Entity>In``      — Request payload received from the client.
    - ``<Entity>Filter``  — Query-parameter filter model for list endpoints.
    - ``Paginated<Entity>`` — Paginated list wrapper.

All timestamps are serialized as ISO 8601 UTC strings.
UUID fields are serialized as standard hyphenated strings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ===========================================================================
# Shared / Utility Schemas
# ===========================================================================


class PaginationParams(BaseModel):
    """Common pagination parameters used by list endpoints."""

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=50, ge=1, le=500, description="Items per page")

    @property
    def offset(self) -> int:
        """Return the SQL OFFSET value for this page."""
        return (self.page - 1) * self.page_size


class PaginatedMeta(BaseModel):
    """Metadata block included in all paginated responses."""

    page: int
    page_size: int
    total_count: int
    total_pages: int


class ErrorDetail(BaseModel):
    """Standardized error response body."""

    error: str = Field(description="Short error code")
    message: str = Field(description="Human-readable description")
    detail: Any | None = Field(default=None, description="Optional structured detail")


# ===========================================================================
# Health & Status
# ===========================================================================


class HealthOut(BaseModel):
    """Response schema for GET /health."""

    status: Literal["ok", "degraded", "error"] = "ok"
    version: str
    timestamp: datetime
    database_reachable: bool
    monitor_running: bool
    poller_running: bool


class DetectorWeightsOut(BaseModel):
    """Per-detector weight breakdown embedded in the status response."""

    file_rename: float
    entropy: float
    process_chain: float
    shadow_copy: float
    network_beacon: float


class ScoringConfigOut(BaseModel):
    """Scoring engine configuration summary."""

    window_seconds: int
    decay_lambda: float
    score_interval_seconds: float
    weights: DetectorWeightsOut


class StatusOut(BaseModel):
    """Response schema for GET /status."""

    current_score: float = Field(ge=0.0, le=100.0)
    severity: str
    response_mode: str
    file_queue_depth: int
    process_queue_depth: int
    engine_running: bool
    watch_paths: list[str]
    scoring_config: ScoringConfigOut
    timestamp: datetime


# ===========================================================================
# FileEvent
# ===========================================================================


class FileEventOut(BaseModel):
    """Response schema for a single FileEvent record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    event_type: str
    file_path: str
    destination_path: str | None
    file_extension: str | None
    entropy_score: float | None
    file_size_bytes: int | None
    process_pid: int | None
    process_name: str | None


class FileEventFilter(BaseModel):
    """Query-parameter filter model for GET /events."""

    event_type: str | None = Field(
        default=None,
        description="Filter by event type: created|modified|deleted|renamed",
    )
    extension: str | None = Field(
        default=None,
        description="Filter by file extension (e.g., .locked)",
    )
    min_entropy: float | None = Field(
        default=None,
        ge=0.0,
        le=8.0,
        description="Minimum entropy score filter",
    )
    since: datetime | None = Field(
        default=None,
        description="Return events after this UTC timestamp",
    )
    until: datetime | None = Field(
        default=None,
        description="Return events before this UTC timestamp",
    )


class PaginatedFileEvents(BaseModel):
    """Paginated list of file events."""

    meta: PaginatedMeta
    items: list[FileEventOut]


# ===========================================================================
# ProcessSnapshot
# ===========================================================================


class ProcessSnapshotOut(BaseModel):
    """Response schema for a single ProcessSnapshot record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    pid: int
    process_name: str
    cpu_percent: float
    memory_mb: float
    disk_write_bytes: int
    exe_path: str | None
    parent_pid: int | None
    parent_name: str | None
    is_flagged: bool
    flag_reason: str | None


# ===========================================================================
# ThreatScore
# ===========================================================================


class ThreatScoreOut(BaseModel):
    """Response schema for a single ThreatScore record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    score: float
    severity_level: str
    triggered_rules: list[str] | None
    signal_breakdown: dict[str, float] | None
    window_start: datetime | None
    window_end: datetime | None


class ScoreTimeSeriesPoint(BaseModel):
    """A single data point in the threat score time series."""

    timestamp: datetime
    score: float
    severity_level: str


class ScoreTimeSeriesOut(BaseModel):
    """Response schema for GET /scores/timeseries."""

    points: list[ScoreTimeSeriesPoint]
    total_points: int
    min_score: float
    max_score: float
    avg_score: float


# ===========================================================================
# Alert
# ===========================================================================


class AlertOut(BaseModel):
    """Response schema for a single Alert record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    alert_type: str
    threat_score_id: UUID
    message: str
    acknowledged: bool
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    raw_context: dict[str, Any] | None


class AlertDismissIn(BaseModel):
    """Request body for POST /alerts/{id}/dismiss."""

    acknowledged_by: str = Field(
        min_length=1,
        max_length=256,
        description="Operator identifier who is acknowledging the alert",
    )
    notes: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional operator note attached to the dismissal",
    )


class PaginatedAlerts(BaseModel):
    """Paginated list of alerts."""

    meta: PaginatedMeta
    items: list[AlertOut]


# ===========================================================================
# Incident
# ===========================================================================


class IncidentOut(BaseModel):
    """Response schema for a single Incident record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    threat_score: float
    severity_level: str
    suspect_process_pid: int | None
    suspect_process_name: str | None
    affected_files_count: int
    affected_extensions: list[str] | None
    quarantine_path: str | None
    response_mode: str
    resolved: bool
    resolved_at: datetime | None
    notes: str | None


class IncidentResolveIn(BaseModel):
    """Request body for POST /incidents/{id}/resolve."""

    notes: str | None = Field(
        default=None,
        max_length=4096,
        description="Post-incident analysis notes",
    )


class PaginatedIncidents(BaseModel):
    """Paginated list of incidents."""

    meta: PaginatedMeta
    items: list[IncidentOut]


# ===========================================================================
# Report
# ===========================================================================


class ReportGenerateIn(BaseModel):
    """Request body for POST /reports/generate."""

    incident_id: UUID = Field(description="UUID of the Incident to generate a report for")
    formats: list[Literal["json", "csv", "pdf"]] = Field(
        default=["json"],
        min_length=1,
        description="One or more output formats to generate",
    )
    include_event_timeline: bool = Field(
        default=True,
        description="Include the full FileEvent timeline in the report",
    )
    include_process_metadata: bool = Field(
        default=True,
        description="Include ProcessSnapshot data in the report",
    )
    include_remediation: bool = Field(
        default=True,
        description="Append the remediation recommendations section",
    )

    @field_validator("formats")
    @classmethod
    def deduplicate_formats(cls, v: list[str]) -> list[str]:
        """Remove duplicate format entries while preserving order."""
        seen: set[str] = set()
        return [fmt for fmt in v if not (fmt in seen or seen.add(fmt))]  # type: ignore[func-returns-value]


class ReportOut(BaseModel):
    """Response schema for a generated report record."""

    incident_id: str
    formats_generated: list[str]
    file_paths: dict[str, str] = Field(
        description="Mapping of format → absolute file path for generated files"
    )
    generated_at: datetime
    sha256_hashes: dict[str, str] = Field(
        description="SHA-256 integrity hash per generated file"
    )


# ===========================================================================
# Scan & Settings
# ===========================================================================


class ScanIn(BaseModel):
    """Request body for POST /scan — trigger a manual scan of a directory."""

    target_path: str = Field(
        min_length=1,
        max_length=4096,
        description="Absolute path to scan. Must be inside a configured watch path.",
    )
    recursive: bool = Field(default=True, description="Scan subdirectories recursively")
    compute_entropy: bool = Field(
        default=True,
        description="Calculate Shannon entropy for each file found",
    )
    max_files: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum number of files to scan in a single request",
    )


class ScanFileResult(BaseModel):
    """Result for a single file in a manual scan."""

    file_path: str
    file_extension: str | None
    file_size_bytes: int
    entropy_score: float | None
    entropy_classification: str | None
    is_suspicious_extension: bool
    is_likely_encrypted: bool


class ScanOut(BaseModel):
    """Response schema for POST /scan."""

    target_path: str
    files_scanned: int
    suspicious_files: list[ScanFileResult]
    high_entropy_files: list[ScanFileResult]
    scan_duration_seconds: float
    timestamp: datetime


class SettingsIn(BaseModel):
    """
    Request body for POST /settings — runtime configuration overrides.

    Only a safe subset of settings may be changed at runtime.
    Structural config (DB URL, watch paths) requires a full restart.
    """

    response_mode: Literal["simulation", "alert", "active"] | None = Field(
        default=None,
        description=(
            "Override response mode. 'active' mode cannot be set via API "
            "(requires config.yaml dual-approval). See PROJECT_RULES.md §3.2."
        ),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] | None = Field(
        default=None,
        description="Override the active log level",
    )
    score_interval_seconds: float | None = Field(
        default=None,
        ge=1.0,
        le=60.0,
        description="Override scoring cycle interval in seconds",
    )


class SettingsOut(BaseModel):
    """Response schema for POST /settings — echoes applied changes."""

    applied_changes: dict[str, Any]
    message: str
    timestamp: datetime


# ===========================================================================
# SSE / Stream Event
# ===========================================================================


class SSEAlertPayload(BaseModel):
    """Payload of a real-time alert event pushed via SSE."""

    event_id: str
    event_type: Literal["alert", "incident", "score_update", "heartbeat"]
    timestamp: datetime
    data: dict[str, Any]
