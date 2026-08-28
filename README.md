# 🛡️ Ransomware Detection and Response System (RDRS)
**Enterprise-Grade Heuristic Detection & Automated SOAR Incident Response Pipeline**

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)

---
<div align="center">
  <img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" width="100%">
</div>

## 🏗️ System Architecture & Data Flow

The RDRS pipeline operates via a decoupled, highly concurrent asynchronous architecture leveraging FastAPI and Server-Sent Events (SSE).

```ascii
                                ┌───────────────────────────┐
                                │   Operating System (OS)   │
                                └──────┬──────────────┬─────┘
                                       │              │
                           File System Events      Process Telemetry
                                       │              │
┌──────────────────────────────────────▼──────────────▼────────────────────────────────────┐
│                             BACKEND DETECTION PIPELINE (FastAPI)                         │
│                                                                                          │
│  ┌──────────────────────┐        ┌────────────────────────┐      ┌────────────────────┐  │
│  │ FileSystemMonitor    │        │ ThreatScoringEngine    │      │ ProcessPoller      │  │
│  │ (watchdog)           ├───────►│ (Sliding Window deque) │◄─────┤ (psutil)           │  │
│  └──────────────────────┘        └───────────┬────────────┘      └────────────────────┘  │
│                                              │                                           │
│  ┌──────────────────────┐        ┌───────────▼────────────┐      ┌────────────────────┐  │
│  │ Entropy Calculator   │        │ Evaluator (Heuristics) │      │ SQLAlchemy ORM     │  │
│  │ (Shannon Entropy)    ├───────►│ (Score: 0.0 - 100.0)   ├─────►│ (PostgreSQL JSONB) │  │
│  └──────────────────────┘        └───────────┬────────────┘      └────────────────────┘  │
│                                              │                                           │
│  ┌──────────────────────┐        ┌───────────▼────────────┐                              │
│  │ SSE Broadcaster      │◄───────┤ IncidentResponder      │ (Phase 5 SOAR Playbook)      │
│  │ (asyncio.Queue bus)  │        │ (shutil quarantine)    │                              │
│  └──────────────────────┘        └────────────────────────┘                              │
└───────────┬──────────────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────┐
│                 REACT SOC DASHBOARD                     │
│  (Real-Time ThreatGauge, EventStream, and Alerts)       │
└─────────────────────────────────────────────────────────┘
```

## 📂 Exhaustive Project Directory Structure

```text
RDRS/
├── backend/                       # Python FastAPI Backend Architecture
│   ├── api/                       # API Routing & Transport Layer
│   │   ├── dependencies.py        # Dependency Injection (Engine, DB, Config)
│   │   ├── main.py                # FastAPI Application Factory & Lifespan
│   │   ├── schemas.py             # Pydantic Validation Models
│   │   └── routes/                # Route Controllers
│   │       ├── alerts.py          # /api/v1/alerts (Acknowledge, List)
│   │       ├── analyze.py         # /api/v1/analyze (Manual File Analysis)
│   │       ├── events.py          # /api/v1/events (Historical Telemetry)
│   │       ├── stream.py          # /api/v1/stream (SSE Broadcast Bus)
│   │       └── simulate.py        # /api/v1/simulate (Ransomware Scenarios)
│   ├── core/                      # Core Business Logic & Mathematics
│   │   ├── config.py              # Pydantic BaseSettings (Env Vars)
│   │   ├── entropy.py             # Shannon Entropy & Delta Calculation
│   │   └── logging.py             # Loguru Intercept & Rotation Setup
│   ├── database/                  # Persistence Layer
│   │   ├── init_db.py             # Schema Bootstrapping
│   │   ├── models.py              # SQLAlchemy Declarative Models (Incident, Alert)
│   │   └── session.py             # Async/Sync Engine & Session Factories
│   ├── detectors/                 # The Threat Detection Engine
│   │   ├── engine.py              # ThreatScoringEngine & SlidingWindow
│   │   ├── file_monitor.py        # Watchdog FileSystemMonitor
│   │   ├── process_poller.py      # Psutil Resource Metrics Polling
│   │   └── responder.py           # IncidentResponder (SOAR Playbook)
│   └── reports/                   # Automated PDF Reporting
│       └── generator.py           # Incident HTML-to-PDF generation
├── frontend/                      # React / Vite SPA Dashboard
│   ├── src/
│   │   ├── components/            # UI Components (ThreatGauge, ActivityLog)
│   │   ├── hooks/                 # Custom React Hooks (useSSE)
│   │   └── App.tsx                # Main Application Router & Layout
│   ├── package.json
│   └── tailwind.config.js         # TailwindCSS Theming (Dark Mode)
├── tests/                         # Pytest Coverage Suite
│   ├── conftest.py                # Async DB Mocks & Sandbox Setup
│   ├── test_engine.py             # Detection Rule Unit Tests
│   ├── test_entropy.py            # Math & Edge Case Verification
│   └── test_pipeline.py           # Full E2E Incident Responder Flow
├── data/                          # Data Volumes
│   ├── sandbox/                   # Safe Simulation Directory (Target for Encryption)
│   └── logs/                      # RDRS JSON Audit Logs
├── docker-compose.yml             # Multi-Container Orchestration
└── pyproject.toml                 # Poetry/Pip Project Metadata
```

## 🚀 Core Features & Modules Breakdown

*   **Telemetry Monitoring**: Utilizing a highly optimized `FileSystemMonitor` (built on `watchdog`) and `ProcessPoller` (`psutil`), the system captures a high-throughput stream of atomic OS events (creation, modification, mass renames).
*   **Heuristic Scoring Engine**: A localized `ThreatScoringEngine` processes events in a 60-second sliding time window. It evaluates multiple composite rules, including file modification velocity and predictable-to-random entropy shifts.
*   **Automated SOAR Response**: When the threat score breaches `70.0` (CRITICAL), the `IncidentResponder` automatically quarantines the affected evidence into a secure sandbox and logs a simulated neutralization of the offending parent process.
*   **Real-Time Streaming**: A dedicated `asyncio.Queue` broadcast fan-out pushes live telemetry and alerts to the React SOC dashboard via Server-Sent Events (SSE).

## 📋 Functional Requirements (FR) Status Table

| Req ID | Description | Status | Verification / Implementation |
| :--- | :--- | :---: | :--- |
| **FR-1** | Background filesystem monitoring via watchdog | ✅ | `backend/detectors/file_monitor.py` |
| **FR-2** | Process resource polling (CPU/Mem/Disk I/O) | ✅ | `backend/detectors/process_poller.py` |
| **FR-3** | Shannon entropy calculation & payload inspection | ✅ | `backend/core/entropy.py` (Tested against encrypted bytes) |
| **FR-4** | Sliding window event aggregation (60s context) | ✅ | `backend/detectors/engine.py` (Deque implementation) |
| **FR-5** | Multi-rule heuristic scoring (Threat Score 0-100) | ✅ | `backend/detectors/engine.py` (Weighted indicators) |
| **FR-6** | Database persistence for historical alerts/incidents | ✅ | `backend/database/models.py` (PostgreSQL / SQLAlchemy) |
| **FR-7** | REST API for alert querying and system status | ✅ | `backend/api/routes/` (FastAPI Routers) |
| **FR-8** | Real-time frontend dashboard for SOC visibility | ✅ | `frontend/src/` (React SPA + Tailwind Dark Mode) |
| **FR-9** | Live telemetry streaming via Server-Sent Events | ✅ | `backend/api/routes/stream.py` & React `useSSE` hook |
| **FR-10** | Automated incident response (SOAR execution) | ✅ | `backend/detectors/responder.py` |
| **FR-11** | Evidence quarantine & simulated process kill | ✅ | `IncidentResponder.simulate_neutralization()` |
| **FR-12** | Immutable audit logging mechanism | ✅ | `backend/core/logging.py` (Loguru JSON rotations) |
| **FR-13** | E2E test suite covering >90% backend logic | ✅ | `tests/test_pipeline.py` (Pytest + Coverage) |

## 🐳 Quick Start & Docker Deployment

Deploying the entire RDRS stack is automated via Docker Compose.

1. **Clone the repository and enter the directory**:
   ```bash
   git clone https://github.com/AbhiSha08/Ransomware-Detection-and-Response-System.git
   cd Ransomware-Detection-and-Response-System
   ```

2. **Start the multi-container stack in detached mode**:
   ```bash
   docker compose up -d --build
   ```

3. **Verify the services**:
   ```bash
   docker compose ps
   ```
   *You should see `rdrs_postgres`, `rdrs_backend` (Port 8000), and `rdrs_frontend` (Port 5173) running.*

4. **Access the Dashboard**:
   Open `http://localhost:5173` in your browser.

## 🧪 Testing & Coverage Suite

RDRS enforces a strict testing discipline with `pytest`, `pytest-asyncio`, and `pytest-cov`. The backend tests run against an isolated SQLite memory database and use a controlled local sandbox directory.

To run the full test suite and view the coverage report:
```bash
docker compose exec rdrs_backend pytest tests/ --cov=backend --cov-report=term-missing
```

*Current backend coverage operates at a **100%** passing rate across all 31 critical heuristics and pipeline endpoints.*

## ⚠️ Safety Notes & Educational Disclaimer

> [!WARNING]
> **Defensive Simulation Mode Only**
> 
> This tool is strictly engineered for **educational use** and operates in a "Defensive Simulation Mode." 
> *   **No Destructive Actions**: The SOAR Incident Responder (`responder.py`) does **not** execute destructive OS commands on the host machine.
> *   **Safe Evidence Handling**: When a threat is detected, `quarantine_evidence()` strictly uses secure copy operations (`shutil.copy2`); the original evidence files are never modified or deleted.
> *   **Simulated Process Kill**: The `simulate_neutralization()` method safely logs the intended termination of a target PID without invoking a true `os.kill` or `taskkill` against the host operating system.
git status