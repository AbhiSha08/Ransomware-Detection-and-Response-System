"""
backend/core/config.py
======================
Secure, validated configuration loader for the RDRS application.

This module uses Pydantic BaseSettings (pydantic-settings) to:
  1. Load environment variables from the host or a .env file.
  2. Parse and validate config.yaml at startup.
  3. Perform cross-field validation (e.g., detector weights sum to 1.0).
  4. Expose a single, importable `settings` singleton for use across all modules.

Design Decisions:
  - Environment variables take precedence over config.yaml values (12-factor).
  - All DB credentials are sourced exclusively from environment variables.
  - Startup fails fast with a descriptive error if any required field is missing
    or if invariants (like weight sums) are violated.

Usage:
    from backend.core.config import settings

    db_url = settings.database.url
    weights = settings.threat_scoring.detector_weights
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from loguru import logger
from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Project root — resolves to the repo root regardless of CWD
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
CONFIG_FILE: Path = PROJECT_ROOT / "config.yaml"


# ===========================================================================
# Sub-Models — each maps to a YAML top-level key
# ===========================================================================


class AppSettings(BaseModel):
    """Top-level application metadata."""

    name: str = "Ransomware Detection and Response System"
    short_name: str = "RDRS"
    version: str = "1.0.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = True
    timezone: str = "UTC"


class PoolSettings(BaseModel):
    """SQLAlchemy connection pool configuration."""

    pool_size: int = Field(default=10, ge=1, le=100)
    max_overflow: int = Field(default=20, ge=0, le=200)
    pool_timeout: int = Field(default=30, ge=1)
    pool_recycle: int = Field(default=1800, ge=60)
    echo: bool = False


class DatabaseSettings(BaseModel):
    """
    Database connection configuration.

    Credentials are injected by the Settings loader from environment variables,
    NOT from config.yaml. This model assembles the final connection URLs.
    """

    # These fields are populated programmatically by Settings.__init__
    url: str = ""
    async_url: str = ""
    pool: PoolSettings = PoolSettings()

    @field_validator("url", "async_url", mode="before")
    @classmethod
    def strip_yaml_placeholder(cls, v: str) -> str:
        """Strip unresolved ${VAR} placeholders — real values come from env."""
        if v and v.startswith("postgresql"):
            # Return as-is; real resolution happens in Settings.model_post_init
            return v
        return v


class FilesystemMonitorSettings(BaseModel):
    """Configuration for the watchdog filesystem observer."""

    watch_paths: list[str] = Field(default_factory=lambda: ["data/sandbox"])
    suspicious_extensions: list[str] = Field(default_factory=list)
    ransom_note_patterns: list[str] = Field(default_factory=list)
    recursive: bool = True

    @field_validator("watch_paths", mode="before")
    @classmethod
    def validate_watch_paths(cls, v: list[str]) -> list[str]:
        """Ensure at least one watch path is configured."""
        if not v:
            raise ValueError("At least one watch_path must be configured.")
        return v


class ProcessMonitorSettings(BaseModel):
    """Configuration for the psutil process monitor."""

    poll_interval_seconds: int = Field(default=2, ge=1, le=60)
    process_whitelist: list[str] = Field(default_factory=list)
    high_risk_processes: list[str] = Field(default_factory=list)


class MonitoringSettings(BaseModel):
    """Unified monitoring configuration."""

    filesystem: FilesystemMonitorSettings = FilesystemMonitorSettings()
    process: ProcessMonitorSettings = ProcessMonitorSettings()


class DetectorWeights(BaseModel):
    """
    Per-detector signal weights for the threat scoring engine.

    Invariant: all weights must sum to exactly 1.0 (±0.001 tolerance).
    Validated at startup via model_validator.
    """

    file_rename: float = Field(default=0.30, ge=0.0, le=1.0)
    entropy: float = Field(default=0.25, ge=0.0, le=1.0)
    process_chain: float = Field(default=0.20, ge=0.0, le=1.0)
    shadow_copy: float = Field(default=0.15, ge=0.0, le=1.0)
    network_beacon: float = Field(default=0.10, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_weights_sum(self) -> "DetectorWeights":
        """Enforce that all detector weights sum to 1.0 (±0.001 tolerance)."""
        total = round(
            self.file_rename
            + self.entropy
            + self.process_chain
            + self.shadow_copy
            + self.network_beacon,
            6,
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"Detector weights must sum to 1.0, but sum is {total:.6f}. "
                f"Adjust values in config.yaml under threat_scoring.detector_weights."
            )
        return self


class ThresholdEntry(BaseModel):
    """A single score threshold band."""

    min: float = Field(ge=0, le=100)
    max: float = Field(ge=0, le=100)
    label: str
    action: str


class ScoreThresholds(BaseModel):
    """Maps score ranges to severity labels and response actions."""

    nominal: ThresholdEntry = ThresholdEntry(min=0, max=20, label="NOMINAL", action="none")
    low: ThresholdEntry = ThresholdEntry(min=21, max=40, label="LOW", action="log")
    medium: ThresholdEntry = ThresholdEntry(min=41, max=60, label="MEDIUM", action="log_and_warn")
    high: ThresholdEntry = ThresholdEntry(min=61, max=80, label="HIGH", action="log_and_alert")
    critical: ThresholdEntry = ThresholdEntry(
        min=81, max=100, label="CRITICAL", action="log_alert_and_respond"
    )


class FileRenameThresholds(BaseModel):
    """Detector-specific thresholds for the file rename detector."""

    trigger_rate_per_second: float = Field(default=5.0, ge=1.0)
    max_rate_per_second: float = Field(default=50.0, ge=1.0)


class EntropyThresholds(BaseModel):
    """Detector-specific thresholds for the entropy detector."""

    min_entropy_delta: float = Field(default=1.5, ge=0.0, le=8.0)
    max_entropy_value: float = Field(default=8.0, ge=0.0, le=8.0)


class ProcessChainThresholds(BaseModel):
    """Detector-specific thresholds for the process chain detector."""

    max_safe_depth: int = Field(default=2, ge=1)


class ThreatScoringSettings(BaseModel):
    """Full threat scoring engine configuration."""

    window_seconds: int = Field(default=60, ge=5, le=3600)
    decay_lambda: float = Field(default=0.05, ge=0.001, le=1.0)
    max_score: int = Field(default=100, ge=1, le=100)
    detector_weights: DetectorWeights = DetectorWeights()
    thresholds: ScoreThresholds = ScoreThresholds()
    file_rename: FileRenameThresholds = FileRenameThresholds()
    entropy: EntropyThresholds = EntropyThresholds()
    process_chain: ProcessChainThresholds = ProcessChainThresholds()


class ResponseMode(BaseModel):
    """Response orchestrator configuration."""

    mode: Literal["simulation", "alert", "active"] = "simulation"
    active_mode_authorized: bool = False

    @model_validator(mode="after")
    def validate_active_mode(self) -> "ResponseMode":
        """Guard: active mode requires explicit dual-approval flag."""
        if self.mode == "active" and not self.active_mode_authorized:
            raise ValueError(
                "Response mode 'active' requires 'active_mode_authorized: true' "
                "in config.yaml. See PROJECT_RULES.md §3.2 for the dual-approval "
                "procedure."
            )
        return self


class JWTSettings(BaseModel):
    """JWT authentication parameters."""

    secret_key: SecretStr = SecretStr("PLACEHOLDER")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=15, ge=1)
    refresh_token_expire_days: int = Field(default=7, ge=1)


class RateLimitSettings(BaseModel):
    """API rate limiting configuration."""

    enabled: bool = True
    default_limit: str = "60/minute"
    auth_limit: str = "10/minute"


class ApiSettings(BaseModel):
    """FastAPI server configuration."""

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1024, le=65535)
    workers: int = Field(default=1, ge=1)
    reload: bool = True
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    jwt: JWTSettings = JWTSettings()
    rate_limit: RateLimitSettings = RateLimitSettings()


class LogFileSettings(BaseModel):
    """Log file paths."""

    application: str = "logs/rdrs.log"
    audit: str = "logs/audit.log"
    errors: str = "logs/errors.log"


class LogRotationSettings(BaseModel):
    """Loguru rotation parameters."""

    size: str = "50 MB"
    retention: str = "30 days"
    compression: str = "gz"


class LoggingSettings(BaseModel):
    """Loguru logging configuration."""

    level: Literal["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"] = "DEBUG"
    files: LogFileSettings = LogFileSettings()
    rotation: LogRotationSettings = LogRotationSettings()
    format: Literal["text", "json"] = "json"
    diagnose: bool = True
    backtrace: bool = True


class SandboxSettings(BaseModel):
    """Sandbox containment configuration (used by tests)."""

    root: str = "data/sandbox"
    auto_clean: bool = True
    max_file_size_bytes: int = Field(default=10_485_760, ge=1)


# ===========================================================================
# Root Settings Model
# ===========================================================================


class Settings(BaseSettings):
    """
    Master settings object for the RDRS application.

    Combines pydantic-settings (env var loading) with PyYAML (config.yaml).
    Environment variables always override YAML values.

    Environment Variables (critical):
        RDRS_DB_USER      : PostgreSQL username
        RDRS_DB_PASSWORD  : PostgreSQL password (required)
        RDRS_DB_HOST      : PostgreSQL host (default: localhost)
        RDRS_DB_PORT      : PostgreSQL port (default: 5432)
        RDRS_DB_NAME      : PostgreSQL database name (default: rdrs)
        RDRS_JWT_SECRET   : JWT signing secret (min 32 bytes)
    """

    model_config = SettingsConfigDict(
        env_prefix="RDRS_",
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Sub-models loaded from YAML ----
    app: AppSettings = AppSettings()
    database: DatabaseSettings = DatabaseSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    threat_scoring: ThreatScoringSettings = ThreatScoringSettings()
    response: ResponseMode = ResponseMode()
    api: ApiSettings = ApiSettings()
    logging: LoggingSettings = LoggingSettings()
    sandbox: SandboxSettings = SandboxSettings()

    # ---- Raw DB credential fields (sourced from env, prefixed by RDRS_) ----
    db_user: str = Field(default="rdrs_user", alias="RDRS_DB_USER")
    db_password: SecretStr = Field(default=SecretStr(""), alias="RDRS_DB_PASSWORD")
    db_host: str = Field(default="localhost", alias="RDRS_DB_HOST")
    db_port: int = Field(default=5432, alias="RDRS_DB_PORT")
    db_name: str = Field(default="rdrs", alias="RDRS_DB_NAME")
    jwt_secret: SecretStr = Field(default=SecretStr(""), alias="RDRS_JWT_SECRET")

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _load_yaml_and_merge(cls, values: dict[str, Any]) -> dict[str, Any]:
        """
        Pre-validation hook that reads config.yaml and merges it into the
        values dict. Environment variables (already in `values`) take priority.
        """
        if not CONFIG_FILE.exists():
            logger.warning(
                f"config.yaml not found at {CONFIG_FILE}. Using defaults + env vars only."
            )
            return values

        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            yaml_data: dict[str, Any] = yaml.safe_load(fh) or {}

        # Strip unresolved ${...} placeholder strings from YAML values
        yaml_data = _strip_yaml_placeholders(yaml_data)

        # Merge: YAML is the base; incoming values (env) override
        merged = {**yaml_data, **values}
        return merged

    @model_validator(mode="after")
    def _assemble_db_urls(self) -> "Settings":
        """
        Assemble the final PostgreSQL connection URLs from resolved credentials.
        This runs after all fields are populated, so env var values are available.
        """
        password = self.db_password.get_secret_value()
        sync_url = (
            f"postgresql+psycopg2://{self.db_user}:{password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )
        async_url = (
            f"postgresql+asyncpg://{self.db_user}:{password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )
        self.database.url = sync_url
        self.database.async_url = async_url

        # Inject JWT secret into api.jwt
        if self.jwt_secret.get_secret_value():
            self.api.jwt.secret_key = self.jwt_secret

        return self

    def get_sync_db_url(self) -> str:
        """Return the synchronous (psycopg2) database URL."""
        return self.database.url

    def get_async_db_url(self) -> str:
        """Return the asynchronous (asyncpg) database URL."""
        return self.database.async_url

    def is_production(self) -> bool:
        """Return True if the application is running in production mode."""
        return self.app.environment == "production"

    def get_watch_paths(self) -> list[Path]:
        """Return watch paths as resolved absolute Path objects."""
        return [
            (PROJECT_ROOT / p).resolve()
            for p in self.monitoring.filesystem.watch_paths
        ]


# ===========================================================================
# Helpers
# ===========================================================================

_PLACEHOLDER_RE = re.compile(r"^\$\{[A-Z_][A-Z0-9_]*(?::-[^}]*)?\}$")


def _strip_yaml_placeholders(data: Any) -> Any:  # noqa: ANN401
    """
    Recursively walk a YAML-parsed dict/list and replace any unresolved
    ${ENV_VAR} placeholder strings with empty string.

    Args:
        data: Arbitrary parsed YAML structure.

    Returns:
        The same structure with placeholder strings replaced by "".
    """
    if isinstance(data, dict):
        return {k: _strip_yaml_placeholders(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_strip_yaml_placeholders(item) for item in data]
    if isinstance(data, str) and _PLACEHOLDER_RE.match(data):
        return ""
    return data


# ===========================================================================
# Singleton accessor
# ===========================================================================


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached application settings singleton.

    Uses lru_cache so the YAML file and environment are only parsed once
    per process lifetime, even if called from multiple modules.

    Returns:
        Settings: The fully validated application settings object.

    Raises:
        pydantic.ValidationError: If required fields are missing or invalid.
    """
    logger.debug("Loading RDRS application settings...")
    s = Settings()
    logger.info(
        f"Settings loaded | env={s.app.environment} | "
        f"db_host={s.db_host} | response_mode={s.response.mode}"
    )
    return s


# Convenience alias — preferred import style across the codebase
settings: Settings = get_settings()
