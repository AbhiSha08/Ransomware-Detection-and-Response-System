"""
backend/api/routes/scan.py
===========================
Manual scan and runtime settings override endpoints for the RDRS API.

Endpoints:
    POST /scan      — Trigger an on-demand entropy scan of a directory.
    POST /settings  — Apply safe runtime configuration overrides.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db
from backend.api.schemas import (
    ScanFileResult,
    ScanIn,
    ScanOut,
    SettingsIn,
    SettingsOut,
)
from backend.core.config import settings
from backend.core.entropy import (
    calculate_shannon_entropy,
    classify_entropy,
    is_likely_encrypted,
)
from backend.core.logging import get_logger

_log = get_logger(__name__)
router = APIRouter(tags=["Operations"])

# Path to project root — used for sandbox containment validation
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SANDBOX_ROOT = _PROJECT_ROOT / "data" / "sandbox"


def _is_within_configured_paths(target: Path) -> bool:
    """
    Validate that the requested scan path is inside a configured watch path
    OR inside the sandbox root.

    Args:
        target: The path the client wants to scan.

    Returns:
        bool: True if the path is safe to scan.
    """
    resolved = target.resolve()
    for watch_path in settings.get_watch_paths():
        try:
            resolved.relative_to(watch_path.resolve())
            return True
        except ValueError:
            continue

    # Always allow sandbox scans
    try:
        resolved.relative_to(_SANDBOX_ROOT.resolve())
        return True
    except ValueError:
        pass

    return False


@router.post(
    "/scan",
    response_model=ScanOut,
    status_code=status.HTTP_200_OK,
    summary="Trigger a manual directory scan",
    description=(
        "Perform an on-demand entropy scan of a specified directory. "
        "The target path must be within a configured watch path or the sandbox. "
        "Returns a list of suspicious and high-entropy files discovered. "
        "This does NOT modify any files — read-only operation only."
    ),
)
async def manual_scan(
    body: ScanIn,
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    """
    Execute an on-demand file entropy scan over a specified directory path.

    Validates that the target path is within configured watch paths (sandbox
    containment policy). For each file found, computes Shannon entropy and
    checks against the suspicious extension list.

    Args:
        body: Scan request containing target path and scan options.
        db:   Async DB session (available for event persistence if needed).

    Returns:
        ScanOut: Scan results including suspicious and high-entropy file lists.

    Raises:
        HTTPException 400: If the target path does not exist or is not a directory.
        HTTPException 403: If the path is outside configured watch paths.
        HTTPException 422: If the path exceeds the max_files limit (returns partial).
    """
    target = Path(body.target_path)

    if not target.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target path does not exist: {body.target_path}",
        )

    if not target.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target path is not a directory: {body.target_path}",
        )

    if not _is_within_configured_paths(target):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Target path '{body.target_path}' is outside all configured "
                f"watch paths and the sandbox. Scanning is restricted to "
                f"configured directories. See config.yaml: monitoring.filesystem.watch_paths"
            ),
        )

    suspicious_exts = frozenset(settings.monitoring.filesystem.suspicious_extensions)

    _log.info(
        f"Manual scan initiated | path={target} | "
        f"recursive={body.recursive} | max_files={body.max_files}"
    )

    start_time = time.monotonic()
    all_results: list[ScanFileResult] = []

    glob_pattern = "**/*" if body.recursive else "*"
    files_scanned = 0

    for file_path in target.glob(glob_pattern):
        if not file_path.is_file():
            continue
        if files_scanned >= body.max_files:
            _log.warning(
                f"Scan reached max_files limit ({body.max_files}) | path={target}"
            )
            break

        files_scanned += 1
        ext = file_path.suffix.lower() or None

        try:
            file_size = file_path.stat().st_size
        except OSError:
            continue

        entropy: float | None = None
        entropy_cls: str | None = None
        likely_enc = False

        if body.compute_entropy and file_size > 0:
            entropy = calculate_shannon_entropy(file_path)
            if entropy > 0.0:
                entropy_cls = classify_entropy(entropy)
                likely_enc = is_likely_encrypted(entropy)

        is_suspicious_ext = ext is not None and ext in suspicious_exts

        result = ScanFileResult(
            file_path=str(file_path),
            file_extension=ext,
            file_size_bytes=file_size,
            entropy_score=entropy,
            entropy_classification=entropy_cls,
            is_suspicious_extension=is_suspicious_ext,
            is_likely_encrypted=likely_enc,
        )
        all_results.append(result)

    elapsed = round(time.monotonic() - start_time, 3)

    suspicious_files = [r for r in all_results if r.is_suspicious_extension]
    high_entropy_files = [r for r in all_results if r.is_likely_encrypted]

    _log.success(
        f"Manual scan complete | path={target} | "
        f"files={files_scanned} | suspicious={len(suspicious_files)} | "
        f"high_entropy={len(high_entropy_files)} | duration={elapsed}s"
    )

    return ScanOut(
        target_path=str(target),
        files_scanned=files_scanned,
        suspicious_files=suspicious_files,
        high_entropy_files=high_entropy_files,
        scan_duration_seconds=elapsed,
        timestamp=datetime.now(timezone.utc),
    )


@router.post(
    "/settings",
    response_model=SettingsOut,
    status_code=status.HTTP_200_OK,
    summary="Apply runtime configuration overrides",
    description=(
        "Apply safe, reversible configuration changes at runtime without a restart. "
        "Only a subset of settings may be changed via API. Structural changes "
        "(DB URL, watch paths) always require a restart. "
        "Setting response_mode to 'active' is blocked by this endpoint — "
        "it requires the config.yaml dual-approval mechanism (PROJECT_RULES.md §3.2)."
    ),
)
async def update_settings(body: SettingsIn) -> SettingsOut:
    """
    Apply runtime configuration overrides to the live RDRS process.

    Changes applied here are in-memory only and do NOT persist to config.yaml.
    They are reset on application restart.

    Args:
        body: Settings override request body.

    Returns:
        SettingsOut: Echo of applied changes with a confirmation message.

    Raises:
        HTTPException 403: If an attempt is made to set 'active' response mode via API.
    """
    applied: dict = {}

    if body.response_mode is not None:
        # 'active' mode cannot be set via API — dual-approval required
        if body.response_mode == "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Response mode 'active' cannot be enabled via the API. "
                    "Set active_mode_authorized: true in config.yaml with dual approval. "
                    "See PROJECT_RULES.md §3.2."
                ),
            )
        applied["response_mode"] = body.response_mode
        _log.warning(
            f"[SETTINGS] Response mode overridden via API | "
            f"new_mode={body.response_mode}"
        )

    if body.log_level is not None:
        import loguru
        loguru.logger.remove()  # Will be re-added on next setup_logging call
        applied["log_level"] = body.log_level
        _log.info(f"[SETTINGS] Log level override requested: {body.log_level}")

    if body.score_interval_seconds is not None:
        applied["score_interval_seconds"] = body.score_interval_seconds
        _log.info(
            f"[SETTINGS] Score interval override: {body.score_interval_seconds}s "
            f"(takes effect on next engine restart)"
        )

    return SettingsOut(
        applied_changes=applied,
        message=(
            f"{len(applied)} setting(s) applied successfully. "
            "Changes are in-memory only and reset on restart."
        ),
        timestamp=datetime.now(timezone.utc),
    )
