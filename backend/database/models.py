"""
backend/database/models.py
==========================
SQLAlchemy ORM models for the RDRS database schema.

Table Summary:
    - FileEvent       : Filesystem events captured by the watchdog monitor.
    - ProcessSnapshot : Point-in-time process metrics from psutil.
    - ThreatScore     : Time-series threat score calculations from the scoring engine.
    - Alert           : Triggered alert records linked to ThreatScore rows.
    - Incident        : Consolidated incident records for operator review and reporting.

Design Decisions:
    - All primary keys use server-side UUID generation (no app-layer UUID collisions).
    - All timestamp columns are TIMESTAMPTZ (UTC) — no naive datetimes in the DB.
    - JSON columns (triggered_rules, affected_files) use native PostgreSQL JSONB
      for efficient querying without full table scans.
    - Enum types are defined as Python Enum classes and mapped to VARCHAR columns
      for portability (no DB-level enum migration required on value addition).
    - All models inherit from `Base` (declarative_base) and include a `__repr__`
      for developer-friendly debugging.
    - Indexes are defined on all foreign keys and high-cardinality filter columns.

Relationships:
    ThreatScore  ──< Alert       (one ThreatScore can trigger many Alerts)
    ThreatScore  ──< Incident    (one ThreatScore per Incident)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

#: Cross-database JSON column type — native JSONB on PostgreSQL, JSON fallback on SQLite
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")



# ===========================================================================
# Declarative Base
# ===========================================================================


class Base(DeclarativeBase):
    """
    Shared declarative base for all RDRS ORM models.

    All models that inherit from this class will be registered in the
    metadata registry and included in `Base.metadata.create_all()` calls.
    """

    pass


# ===========================================================================
# Enum Definitions
# ===========================================================================


class FileEventType(str, Enum):
    """
    Filesystem event types captured by the watchdog observer.

    Values correspond to watchdog event class names (normalized to lowercase).
    """

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"       # Watchdog `moved` event (src → dst rename)
    PERMISSION_CHANGE = "permission_change"


class SeverityLevel(str, Enum):
    """
    Severity classification for threat scores.

    Maps to score ranges defined in config.yaml under threat_scoring.thresholds.
    """

    NOMINAL = "NOMINAL"     # Score 0–20: normal baseline activity
    LOW = "LOW"             # Score 21–40: slightly elevated, log only
    MEDIUM = "MEDIUM"       # Score 41–60: notable activity, dashboard warning
    HIGH = "HIGH"           # Score 61–80: significant threat, alert generated
    CRITICAL = "CRITICAL"   # Score 81–100: active threat, response triggered


class AlertType(str, Enum):
    """Alert categories corresponding to detector signal sources."""

    FILE_RENAME_SPIKE = "FILE_RENAME_SPIKE"
    HIGH_ENTROPY_DETECTED = "HIGH_ENTROPY_DETECTED"
    SUSPICIOUS_PROCESS_CHAIN = "SUSPICIOUS_PROCESS_CHAIN"
    SHADOW_COPY_DELETION = "SHADOW_COPY_DELETION"
    NETWORK_BEACON_DETECTED = "NETWORK_BEACON_DETECTED"
    RANSOM_NOTE_CREATED = "RANSOM_NOTE_CREATED"
    SCORE_THRESHOLD_CROSSED = "SCORE_THRESHOLD_CROSSED"


class ResponseMode(str, Enum):
    """Response mode active at the time an Incident was recorded."""

    SIMULATION = "simulation"
    ALERT = "alert"
    ACTIVE = "active"


# ===========================================================================
# Model: FileEvent
# ===========================================================================


class FileEvent(Base):
    """
    Represents a single filesystem event observed by the watchdog monitor.

    Each row is immutable once inserted (append-only log pattern). Updates
    and deletes on this table are forbidden by application-layer convention.

    Attributes:
        id:              UUID primary key (server-generated).
        timestamp:       UTC datetime when the event was captured.
        event_type:      Nature of the filesystem event (create/modify/delete/rename).
        file_path:       Absolute path to the affected file (source path for renames).
        destination_path: Destination path for rename events; NULL otherwise.
        file_extension:  Lowercase file extension at event time (e.g., ".docx").
        entropy_score:   Shannon entropy of the file at event time (0.0–8.0).
                         NULL if entropy calculation was skipped (e.g., on delete).
        file_size_bytes: File size in bytes at event time; NULL if unavailable.
        process_pid:     PID of the process that triggered the event (best-effort).
        process_name:    Name of the triggering process (best-effort).
    """

    __tablename__ = "file_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Unique event identifier (UUID v4)",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="UTC timestamp of event capture",
    )
    event_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Filesystem event type: created|modified|deleted|renamed|permission_change",
    )
    file_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Absolute path of the affected file (source path for renames)",
    )
    destination_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Destination path for rename/move events; NULL otherwise",
    )
    file_extension: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Lowercase file extension at event time (e.g., .docx, .locked)",
    )
    entropy_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Shannon entropy of file content (0.0–8.0); NULL if not calculated",
    )
    file_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment="File size in bytes at event time",
    )
    process_pid: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="PID of the process that triggered the event (best-effort)",
    )
    process_name: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        comment="Name of the triggering process (best-effort)",
    )

    # --- Indexes ---
    __table_args__ = (
        Index("ix_file_events_timestamp_type", "timestamp", "event_type"),
        Index("ix_file_events_extension_ts", "file_extension", "timestamp"),
        {"comment": "Append-only log of all filesystem events observed by the watchdog monitor"},
    )

    def __repr__(self) -> str:
        return (
            f"<FileEvent id={self.id!s:.8} type={self.event_type!r} "
            f"path={self.file_path!r} ts={self.timestamp}>"
        )


# ===========================================================================
# Model: ProcessSnapshot
# ===========================================================================


class ProcessSnapshot(Base):
    """
    Point-in-time snapshot of a running process's resource metrics.

    Recorded by the psutil process monitor on each polling cycle for any
    process that exceeds configured resource thresholds or appears on the
    high-risk process list.

    Attributes:
        id:               UUID primary key.
        timestamp:        UTC datetime of the snapshot.
        pid:              Operating system process ID.
        process_name:     Process executable name (without path or extension).
        cpu_percent:      CPU utilization percentage at snapshot time (0.0–100.0+).
        memory_mb:        Resident set size (RSS) in megabytes.
        disk_write_bytes: Cumulative disk write bytes since process start.
        exe_path:         Absolute path to the process executable.
        parent_pid:       PID of the parent process; NULL for root processes.
        parent_name:      Name of the parent process (denormalized for query speed).
        cmdline:          Full command line string (space-joined argv list).
        is_flagged:       True if this process triggered a detector signal.
        flag_reason:      Human-readable reason for flagging; NULL if not flagged.
    """

    __tablename__ = "process_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Unique snapshot identifier (UUID v4)",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="UTC timestamp of the process snapshot",
    )
    pid: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
        comment="OS process ID at snapshot time",
    )
    process_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="Process executable name (e.g., explorer, powershell)",
    )
    cpu_percent: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="CPU utilization percentage at snapshot time",
    )
    memory_mb: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Resident set size (RSS) in megabytes",
    )
    disk_write_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        comment="Cumulative disk write bytes since process start",
    )
    exe_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Absolute path to the process executable",
    )
    parent_pid: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="PID of the parent process; NULL for root/orphan processes",
    )
    parent_name: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        comment="Name of the parent process (denormalized)",
    )
    cmdline: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Full command line string (space-joined argv)",
    )
    is_flagged: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if this snapshot triggered a detector signal",
    )
    flag_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable reason for flagging; NULL if not flagged",
    )

    __table_args__ = (
        Index("ix_process_snapshots_pid_ts", "pid", "timestamp"),
        Index("ix_process_snapshots_flagged", "is_flagged", "timestamp"),
        {"comment": "Point-in-time process metric snapshots from the psutil monitor"},
    )

    def __repr__(self) -> str:
        return (
            f"<ProcessSnapshot id={self.id!s:.8} pid={self.pid} "
            f"name={self.process_name!r} ts={self.timestamp}>"
        )


# ===========================================================================
# Model: ThreatScore
# ===========================================================================


class ThreatScore(Base):
    """
    Time-series record of threat score calculations produced by the scoring engine.

    A new row is inserted each time the scoring engine recalculates the score
    (driven by incoming events). This table is the primary data source for the
    dashboard's real-time threat gauge and historical chart.

    Attributes:
        id:               UUID primary key.
        timestamp:        UTC datetime of the score calculation.
        score:            Weighted threat score value (0.0–100.0).
        severity_level:   Severity band derived from the score value.
        triggered_rules:  JSONB array of detector names that contributed signals.
        signal_breakdown: JSONB object of per-detector signal values at calculation time.
        window_start:     UTC start of the sliding window that produced this score.
        window_end:       UTC end of the sliding window (= timestamp).

    Relationships:
        alerts:    Alert records triggered by this score calculation.
        incidents: Incident record linked to this score (at most one).
    """

    __tablename__ = "threat_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Unique threat score record identifier (UUID v4)",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="UTC timestamp of the score calculation",
    )
    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Weighted threat score (0.0–100.0)",
    )
    severity_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
        comment="Severity band: NOMINAL | LOW | MEDIUM | HIGH | CRITICAL",
    )
    triggered_rules: Mapped[list[Any] | None] = mapped_column(
        JSON_TYPE,
        nullable=True,
        comment='JSON array of detector names that contributed signals (e.g., ["file_rename", "entropy"])',
    )
    signal_breakdown: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_TYPE,
        nullable=True,
        comment="JSON object of per-detector raw signal values at calculation time",
    )
    window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC start timestamp of the sliding scoring window",
    )
    window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC end timestamp of the sliding scoring window (= timestamp)",
    )

    # --- Relationships ---
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="threat_score",
        cascade="all, delete-orphan",
        lazy="select",
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        back_populates="threat_score_record",
        uselist=False,
        lazy="select",
    )

    __table_args__ = (
        Index("ix_threat_scores_severity_ts", "severity_level", "timestamp"),
        Index("ix_threat_scores_score", "score"),
        {"comment": "Time-series of threat score calculations for dashboard charting and incident correlation"},
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatScore id={self.id!s:.8} score={self.score:.1f} "
            f"severity={self.severity_level!r} ts={self.timestamp}>"
        )


# ===========================================================================
# Model: Alert
# ===========================================================================


class Alert(Base):
    """
    A triggered alert record linked to a specific ThreatScore calculation.

    Alerts are generated by the ResponseOrchestrator when a ThreatScore
    crosses a configured threshold. Each alert has an acknowledgment state
    that operators manage via the dashboard.

    Attributes:
        id:               UUID primary key.
        timestamp:        UTC datetime the alert was generated.
        alert_type:       Category of threat signal that triggered the alert.
        threat_score_id:  FK reference to the ThreatScore that caused this alert.
        message:          Human-readable alert description for the dashboard.
        acknowledged:     True once an operator has reviewed and dismissed the alert.
        acknowledged_at:  UTC timestamp of acknowledgment; NULL if unacknowledged.
        acknowledged_by:  Operator identifier who acknowledged (user ID or username).
        raw_context:      JSONB blob of detector-specific context data at alert time.
    """

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Unique alert identifier (UUID v4)",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="UTC timestamp when the alert was generated",
    )
    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Alert category (e.g., FILE_RENAME_SPIKE, HIGH_ENTROPY_DETECTED)",
    )
    threat_score_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_scores.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="FK: ThreatScore record that triggered this alert",
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Human-readable alert description for dashboard display",
    )
    acknowledged: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="True once an operator has reviewed and dismissed the alert",
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of alert acknowledgment; NULL if unacknowledged",
    )
    acknowledged_by: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        comment="Operator identifier who acknowledged the alert",
    )
    raw_context: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_TYPE,
        nullable=True,
        comment="JSON blob of detector-specific context data at alert time",
    )

    # --- Relationships ---
    threat_score: Mapped["ThreatScore | None"] = relationship(
        "ThreatScore",
        back_populates="alerts",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_alerts_acknowledged_ts", "acknowledged", "timestamp"),
        Index("ix_alerts_type_ts", "alert_type", "timestamp"),
        {"comment": "Triggered alert records linked to threat score calculations"},
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id!s:.8} type={self.alert_type!r} "
            f"ack={self.acknowledged} ts={self.timestamp}>"
        )


# ===========================================================================
# Model: Incident
# ===========================================================================


class Incident(Base):
    """
    A consolidated incident record representing a confirmed or suspected
    ransomware event requiring operator attention.

    Incidents are created by the ResponseOrchestrator when a ThreatScore
    reaches the CRITICAL or HIGH threshold. They aggregate alert context and
    provide a single entity for report generation and post-incident analysis.

    Attributes:
        id:                   UUID primary key.
        timestamp:            UTC datetime the incident was declared.
        threat_score:         Peak threat score value at incident declaration.
        severity_level:       Severity at incident declaration time.
        threat_score_id:      FK to the ThreatScore row that triggered declaration.
        suspect_process_pid:  PID of the primary suspect process at declaration time.
        suspect_process_name: Name of the primary suspect process.
        affected_files_count: Number of unique files involved in the incident window.
        affected_extensions:  JSONB array of distinct file extensions observed.
        quarantine_path:      Path where quarantined files/processes are staged;
                              NULL in simulation mode.
        response_mode:        Response mode active at incident declaration time.
        resolved:             True once the incident is closed by an operator.
        resolved_at:          UTC timestamp of resolution; NULL if unresolved.
        notes:                Free-text operator notes attached to the incident.
    """

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Unique incident identifier (UUID v4)",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="UTC timestamp of incident declaration",
    )
    threat_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Peak threat score value at the time of incident declaration",
    )
    severity_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
        comment="Severity at incident declaration: HIGH | CRITICAL",
    )
    threat_score_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_scores.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="FK: ThreatScore row that triggered incident declaration",
    )
    suspect_process_pid: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="PID of the primary suspect process at declaration time",
    )
    suspect_process_name: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        comment="Name of the primary suspect process",
    )
    affected_files_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of unique files involved in the incident window",
    )
    affected_extensions: Mapped[list[Any] | None] = mapped_column(
        JSON_TYPE,
        nullable=True,
        comment='JSON array of distinct file extensions observed (e.g., [".docx", ".locked"])',
    )
    quarantine_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Filesystem path where quarantined artifacts are staged; NULL in simulation mode",
    )
    response_mode: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ResponseMode.SIMULATION.value,
        comment="Response mode active at incident declaration: simulation | alert | active",
    )
    resolved: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="True once the incident is closed/resolved by an operator",
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of incident resolution; NULL if still open",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text operator notes for post-incident analysis",
    )

    # --- Relationships ---
    threat_score_record: Mapped["ThreatScore | None"] = relationship(
        "ThreatScore",
        back_populates="incident",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_incidents_resolved_ts", "resolved", "timestamp"),
        Index("ix_incidents_severity_ts", "severity_level", "timestamp"),
        {"comment": "Consolidated incident records for operator review and report generation"},
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id!s:.8} score={self.threat_score:.1f} "
            f"severity={self.severity_level!r} resolved={self.resolved}>"
        )
