"""
backend/api/routes/analyze.py
================================
Artifact Sandbox — File Analysis Endpoint for the RDRS SOAR platform.

POST /api/v1/analyze

Accepts a multipart file upload, quarantines it to a sandboxed directory,
and performs instant forensic analysis using the RDRS entropy engine. The
result contains entropy score, risk classification, and extension-based IOC
matching against the configured suspicious extensions list.

Security Controls:
  - Files are saved ONLY inside /app/data/sandbox/quarantine/ — never
    outside the sandbox boundary.
  - Filename is sanitized (Path().name) to prevent path traversal attacks.
  - File size is bounded to MAX_UPLOAD_BYTES to prevent disk exhaustion.
  - UploadFile is always closed/cleaned up in a finally block.
  - No file is executed or opened beyond binary read for entropy sampling.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiofiles

from fastapi import APIRouter, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from backend.core.config import settings
from backend.core.entropy import calculate_shannon_entropy, classify_entropy, is_likely_encrypted
from backend.core.logging import get_logger

_log = get_logger(__name__)

router = APIRouter(tags=["Artifact Analysis"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hard upload size limit — 50 MB.  Prevents disk-exhaustion DoS.
MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB

#: Quarantine directory inside the Docker sandbox volume.
#: This path is absolute inside the container (/app maps to project root).
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent
_QUARANTINE_DIR: Path = _PROJECT_ROOT / "data" / "sandbox" / "quarantine"

# Risk thresholds aligned with RDRS engine bands
_ENTROPY_CRITICAL: float = 7.0   # Likely encrypted — HIGH risk
_ENTROPY_WARNING:  float = 5.5   # Compressed / suspicious — MEDIUM risk


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_risk_level(
    entropy: float,
    has_suspicious_extension: bool,
    is_encrypted: bool,
) -> str:
    """
    Derive a human-readable RISK_LEVEL from entropy and extension signals.

    Risk escalation logic:
      - HIGH   → entropy ≥ 7.0 OR file has a known ransomware extension
      - MEDIUM → entropy ≥ 5.5 (compressed data, partial encryption)
      - LOW    → entropy < 5.5 and no suspicious extension

    Args:
        entropy:                  Shannon entropy of the uploaded file.
        has_suspicious_extension: True if the extension matches config list.
        is_encrypted:             True if entropy >= 7.0 threshold.

    Returns:
        str: One of 'HIGH', 'MEDIUM', 'LOW'.
    """
    if is_encrypted or has_suspicious_extension:
        return "HIGH"
    if entropy >= _ENTROPY_WARNING:
        return "MEDIUM"
    return "LOW"


def _get_suspicious_extensions() -> frozenset[str]:
    """
    Load suspicious extensions from the settings object (sourced from
    config.yaml) and return as a frozenset of lowercase strings.
    """
    try:
        raw: list[str] = settings.monitoring.filesystem.suspicious_extensions
        return frozenset(ext.lower() for ext in raw)
    except AttributeError:
        _log.warning("Could not load suspicious_extensions from settings — using defaults.")
        return frozenset({
            ".locked", ".encrypted", ".enc", ".rdm", ".crypt", ".crypto",
            ".crypted", ".ezz", ".exx", ".zzz", ".xyz", ".aaa", ".abc",
            ".micro", ".vvv", ".wncry", ".wnry", ".locky", ".zepto",
        })


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    summary="Upload a file for instant entropy and IOC analysis",
    description=(
        "Accepts a multipart/form-data file upload. "
        "Saves it to `data/sandbox/quarantine/` with a UUID-prefixed name to prevent "
        "filename collisions and path traversal. "
        "Computes Shannon entropy and evaluates the extension against the RDRS suspicious "
        "extension list. Returns a structured forensic analysis result with risk level. "
        "Max upload size: 50 MB."
    ),
    responses={
        200: {"description": "Analysis complete — result returned"},
        413: {"description": "File exceeds 50 MB size limit"},
        500: {"description": "Internal error during analysis"},
    },
)
async def analyze_artifact(file: UploadFile) -> JSONResponse:
    """
    POST /api/v1/analyze

    Endpoint entry point. Receives the uploaded UploadFile, delegates to
    analysis logic, and returns a clean JSON forensics report.

    Args:
        file: FastAPI UploadFile object from multipart/form-data.

    Returns:
        JSONResponse: Forensic analysis report with filename, size, entropy,
                      entropy_class, risk_level, is_suspicious_extension,
                      and is_likely_encrypted flags.
    """
    analysis_id = str(uuid.uuid4())
    received_at = datetime.now(timezone.utc)

    # ── 1. Sanitise filename (prevent path traversal) ───────────────────────
    raw_name: str = file.filename or "unknown_upload"
    safe_name: str = Path(raw_name).name          # strips any directory components
    file_extension: str = Path(safe_name).suffix.lower()
    quarantine_name: str = f"{analysis_id[:8]}_{safe_name}"

    _log.info(
        f"Artifact upload received | id={analysis_id[:8]} "
        f"| filename={safe_name} | ext={file_extension}"
    )

    # ── 2. Ensure quarantine directory exists ───────────────────────────────
    _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    quarantine_path: Path = _QUARANTINE_DIR / quarantine_name

    # ── 3. Stream file to quarantine, enforce size limit ───────────────────
    file_size_bytes: int = 0
    try:
        async with aiofiles.open(quarantine_path, "wb") as dest:
            while chunk := await file.read(65536):   # 64 KB chunks
                file_size_bytes += len(chunk)
                if file_size_bytes > MAX_UPLOAD_BYTES:
                    _log.warning(
                        f"Upload rejected — exceeded size limit | "
                        f"id={analysis_id[:8]} | limit={MAX_UPLOAD_BYTES}B"
                    )
                    quarantine_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB upload limit. "
                            "Upload a smaller sample for analysis."
                        ),
                    )
                await dest.write(chunk)
    except HTTPException:
        raise
    except OSError as exc:
        _log.error(f"Failed to write quarantine file | id={analysis_id[:8]} | error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server I/O error during file quarantine. Please retry.",
        )
    finally:
        await file.close()

    # ── 4. Entropy analysis ─────────────────────────────────────────────────
    try:
        loop = asyncio.get_running_loop()
        entropy_score: float = await loop.run_in_executor(
            None, calculate_shannon_entropy, quarantine_path
        )
        entropy_class: str   = classify_entropy(entropy_score)
        encrypted_flag: bool = is_likely_encrypted(entropy_score)
    except Exception as exc:
        _log.error(f"Entropy calculation failed | id={analysis_id[:8]} | error={exc}")
        # Do not expose internal error details to client
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Entropy analysis failed. File may be unreadable or corrupted.",
        )

    # ── 5. Extension IOC matching ───────────────────────────────────────────
    suspicious_extensions: frozenset[str] = _get_suspicious_extensions()
    is_suspicious_ext: bool = file_extension in suspicious_extensions

    # ── 6. Risk classification ──────────────────────────────────────────────
    risk_level: str = _compute_risk_level(
        entropy=entropy_score,
        has_suspicious_extension=is_suspicious_ext,
        is_encrypted=encrypted_flag,
    )

    _log.success(
        f"Artifact analysis complete | id={analysis_id[:8]} "
        f"| file={safe_name} | size={file_size_bytes}B "
        f"| entropy={entropy_score:.4f} | risk={risk_level}"
    )

    return JSONResponse(
        status_code=200,
        content={
            "analysis_id":            analysis_id,
            "timestamp":              received_at.isoformat(),
            "filename":               safe_name,
            "file_size_bytes":        file_size_bytes,
            "file_extension":         file_extension or "(none)",
            "entropy_score":          round(entropy_score, 4),
            "entropy_class":          entropy_class,
            "is_likely_encrypted":    encrypted_flag,
            "is_suspicious_extension": is_suspicious_ext,
            "risk_level":             risk_level,
            "quarantine_path":        str(quarantine_path.relative_to(_PROJECT_ROOT)),
        },
    )
