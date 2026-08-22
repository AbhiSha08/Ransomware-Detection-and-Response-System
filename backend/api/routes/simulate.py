"""
backend/api/routes/simulate.py
================================
SOAR Simulation Endpoint — POST /api/v1/simulate

Executes the project-root simulate_attack.py script as a sandboxed
subprocess inside data/sandbox/. This endpoint is strictly defensive:
  - The script may only write to data/sandbox/ (enforced by simulate_attack.py).
  - The subprocess is killed if it exceeds the execution time limit.
  - stdout/stderr are captured and returned; no raw exception tracebacks
    are leaked to the client.

Security Controls:
  - Only the whitelisted script path can be executed.
  - stdin is closed (subprocess.DEVNULL) to prevent injection.
  - A hard timeout of 60 seconds kills runaway processes.
  - Process is run without shell=True to prevent shell injection.
"""

from __future__ import annotations

import asyncio
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.core.logging import get_logger

_log = get_logger(__name__)

router = APIRouter(tags=["SOAR"])

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Absolute path to the project root (four levels up from this file)
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent

# The ONLY script that this endpoint is permitted to execute
_ALLOWED_SCRIPT: Path = _PROJECT_ROOT / "scripts" / "simulate_attack.py"

# Maximum wall-clock seconds before we SIGKILL the subprocess
_TIMEOUT_SECONDS: int = 60


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/simulate",
    summary="Execute sandboxed ransomware attack simulation",
    description=(
        "Launches `simulate_attack.py` as a subprocess inside `data/sandbox/`. "
        "The script creates benign target files, rewrites them with high-entropy "
        "random bytes, and renames them with ransomware extensions to exercise "
        "the full RDRS detection pipeline. "
        "All file I/O is strictly contained within `data/sandbox/`."
    ),
    responses={
        200: {"description": "Simulation completed successfully"},
        500: {"description": "Simulation script exited with non-zero code or timed out"},
    },
)
async def run_simulation() -> JSONResponse:
    """
    POST /api/v1/simulate

    Runs the ransomware simulation script asynchronously using
    asyncio.create_subprocess_exec. Captures stdout/stderr, enforces a
    hard 60-second timeout, and returns a structured JSON result.

    Returns:
        JSONResponse: Contains 'status', 'stdout', 'stderr', 'exit_code',
                      'duration_seconds', and 'timestamp' fields.
    """
    started_at = datetime.now(timezone.utc)
    _log.info(f"SOAR simulation requested | script={_ALLOWED_SCRIPT}")

    # Guard: ensure the script exists before attempting to execute
    if not _ALLOWED_SCRIPT.exists():
        _log.error(f"Simulation script not found | path={_ALLOWED_SCRIPT}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Simulation script not found. Ensure simulate_attack.py exists.",
                "script_path": str(_ALLOWED_SCRIPT),
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "duration_seconds": 0.0,
                "timestamp": started_at.isoformat(),
            },
        )

    # Build the argv list — no shell, no injection surface
    argv: list[str] = [sys.executable, str(_ALLOWED_SCRIPT)]
    _log.debug(f"Spawning subprocess | argv={shlex.join(argv)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,   # Close stdin — no injection
            cwd=str(_PROJECT_ROOT),              # Run from project root
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            _log.error(f"Simulation timed out after {_TIMEOUT_SECONDS}s — process killed.")
            return JSONResponse(
                status_code=500,
                content={
                    "status": "timeout",
                    "message": f"Simulation exceeded {_TIMEOUT_SECONDS}s limit and was terminated.",
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Process killed after {_TIMEOUT_SECONDS}s timeout.",
                    "duration_seconds": round(elapsed, 3),
                    "timestamp": started_at.isoformat(),
                },
            )

        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
        exit_code = proc.returncode
        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")

        if exit_code == 0:
            _log.success(
                f"Simulation completed | exit_code={exit_code} | "
                f"duration={elapsed:.2f}s"
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "message": "Ransomware simulation completed successfully.",
                    "exit_code": exit_code,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "duration_seconds": round(elapsed, 3),
                    "timestamp": started_at.isoformat(),
                },
            )
        else:
            _log.warning(
                f"Simulation exited non-zero | exit_code={exit_code} | "
                f"stderr={stderr_str[:200]}"
            )
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": f"Simulation script exited with code {exit_code}.",
                    "exit_code": exit_code,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "duration_seconds": round(elapsed, 3),
                    "timestamp": started_at.isoformat(),
                },
            )

    except FileNotFoundError:
        _log.exception("Python interpreter not found for subprocess execution.")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Python interpreter not found. Check server environment.",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "duration_seconds": 0.0,
                "timestamp": started_at.isoformat(),
            },
        )
    except Exception as exc:  # pragma: no cover
        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
        _log.exception(f"Unexpected error during simulation execution: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "An unexpected server error occurred during simulation.",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "duration_seconds": round(elapsed, 3),
                "timestamp": started_at.isoformat(),
            },
        )
