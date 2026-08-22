# RDRS — Project Rules & Operational Directives

> **Classification:** Internal Engineering Directive  
> **Version:** 1.0.0  
> **Effective Date:** 2026-08-13  
> **Author:** RDRS Core Team  
> **Status:** MANDATORY — All contributors must read and acknowledge before committing code.

---

## 1. Mission Statement

The **Ransomware Detection and Response System (RDRS)** is a **purely defensive cybersecurity application**. Its sole purpose is to monitor, detect, analyze, and report ransomware-like behavior in controlled and production environments. This system is a Security Operations Center (SOC) tool — not an offensive instrument.

---

## 2. Absolute Prohibitions (Non-Negotiable)

The following rules are **inviolable**. Any violation constitutes a critical security incident and will result in immediate code removal and contributor review.

| # | Rule | Rationale |
|---|------|-----------|
| **R-001** | **NEVER write, generate, execute, or simulate real malware payloads.** | Prevents RDRS from becoming an attack tool. |
| **R-002** | **NEVER implement encryption routines that target user or system files.** | File encryption is the core ransomware mechanism and must not exist in this codebase. |
| **R-003** | **NEVER exfiltrate data from the monitored host to any external endpoint.** | Preserves privacy and prevents the tool from acting as spyware. |
| **R-004** | **NEVER disable, bypass, or tamper with OS-level security controls** (e.g., Windows Defender, SELinux, AppArmor). | Maintains the integrity of the host's defenses. |
| **R-005** | **NEVER operate in automated kill/quarantine mode outside of explicit operator approval.** | Automated response must default to `SIMULATION` mode to prevent false-positive damage. |
| **R-006** | **NEVER hardcode secrets, credentials, or API keys** directly in source code. | All secrets must be managed via environment variables or a secrets manager. |
| **R-007** | **NEVER commit files from `data/sandbox/` to version control.** | The sandbox directory contains test artifacts that must remain local. |
| **R-008** | **NEVER run test suites against the host's live file system.** | All filesystem tests must execute exclusively within `data/sandbox/`. |

---

## 3. Development Environment Rules

### 3.1 Testing Containment
- **ALL** automated tests must target the `data/sandbox/` directory exclusively.
- The `tests/` directory must contain a `conftest.py` that programmatically enforces the sandbox path.
- No test may perform file I/O outside of `data/sandbox/` or a `tmp_path` pytest fixture.
- Sandbox contents are ephemeral: the `tests/` teardown must clean up all generated artifacts.

### 3.2 Automated Response Policy
- The `RESPONSE_MODE` configuration key defaults to `"simulation"`.
- Valid modes: `"simulation"` (log only) | `"alert"` (log + notify) | `"active"` (log + notify + isolate).
- The `"active"` mode requires a **dual-approval override** in `config.yaml` and cannot be enabled by a single operator.
- Any response action taken in `"active"` mode must be written to the audit log **before** execution.

### 3.3 Code Quality Standards
- **Python Version:** 3.12+ (use `match/case`, type hints, `dataclasses`).
- **Linting:** `ruff` for linting + `black` for formatting. Pre-commit hooks required.
- **Type Safety:** All public functions must have full type annotations. `mypy --strict` must pass.
- **Logging:** Use `loguru` exclusively. No `print()` statements in production code. Log levels must be contextually appropriate.
- **Docstrings:** Google-style docstrings on all modules, classes, and public methods.
- **Test Coverage:** Minimum **80% code coverage** enforced by `pytest-cov`. PRs below this threshold will not be merged.

### 3.4 Database Rules
- **All schema changes** must be managed via Alembic migrations. Direct `CREATE TABLE` in application code is forbidden post-initialization.
- **No raw SQL strings** in application logic. Use SQLAlchemy ORM or Core expressions.
- Database credentials must never appear in `config.yaml` in plaintext; use `${ENV_VAR}` substitution pattern.

### 3.5 API Security Rules
- All FastAPI endpoints must validate input via **Pydantic v2** models.
- Authentication is required on all non-health-check endpoints (JWT Bearer tokens).
- Rate limiting must be applied to all public-facing endpoints.
- CORS origins must be explicitly allowlisted; wildcard `*` origins are forbidden in production.

---

## 4. Git Workflow

```
main           <- Production-stable. Protected branch. Requires PR + 1 reviewer approval.
develop        <- Integration branch. All feature branches merge here.
feature/<name> <- Individual feature development.
hotfix/<name>  <- Critical production patches only.
```

- **Commit messages** must follow Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `security:`.
- **Signed commits** (`git commit -S`) are required for all merges to `main`.

---

## 5. Threat Model Boundaries

RDRS detects **behavioral indicators** consistent with ransomware, including:

- High-frequency file rename/delete operations
- Mass entropy increase across monitored file extensions
- Shadow copy deletion attempts (`vssadmin`, `wmic`)
- Suspicious process spawning chains (e.g., `cmd.exe` -> `powershell.exe` -> unknown child)
- Network connections to known C2 IP ranges
- Registry modification of startup keys from non-standard processes

RDRS does **not** perform:
- Deep packet inspection (DPI)
- Memory forensics (out of scope for v1.0)
- EDR-level kernel hooking

---

## 6. Contributor Acknowledgment

By submitting a pull request to this repository, you confirm that you have read, understood, and agree to comply with all directives in this document.

---

*This document is subject to revision. Check `CHANGELOG.md` for version history.*
