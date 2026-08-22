# Ransomware Detection and Response System (RDRS) 🛡️

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18+](https://img.shields.io/badge/React-18%2B-61DAFB.svg)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg)](https://www.docker.com/)

**RDRS** is an enterprise-grade, real-time defensive cybersecurity application designed to detect, analyze, score, and mitigate ransomware activity on local file systems. Built on a modern asynchronous tech stack featuring **FastAPI**, **PostgreSQL**, and a **React/Vite** SOC dashboard powered by **SSE streaming**, this project delivers full Security Orchestration, Automation, and Response (SOAR) capabilities.

---

## 🏗️ Core Features

*   **Detection**: Captures real-time file system mutations via `watchdog` monitoring and sliding-window event aggregation.
*   **Threat Assessment**: Executes mathematical heuristics including Shannon Entropy calculations and weighted algorithmic scoring to evaluate the probability of an active ransomware payload.
*   **Incident Response**: Integrates a robust SOAR Incident Responder (`responder.py`) capable of executing evidence quarantine and simulated process neutralization without destructive OS actions.
*   **Live Monitoring**: Employs a Server-Sent Events (SSE) stream to push instantaneous, low-latency threat scores and telemetry directly to a React-based Security Operations Center (SOC) dashboard.

---

## 📋 Functional Requirements (FR) Status

The RDRS platform fulfills the original 13 Functional Requirements defined in the core System Specification:

| ID | Requirement | Status |
| :--- | :--- | :---: |
| **FR-1** | Implement a continuous filesystem monitor (Watchdog). | ✅ Completed |
| **FR-2** | Track granular file events (CREATE, MODIFY, RENAME, DELETE). | ✅ Completed |
| **FR-3** | Implement high-entropy calculation algorithms for detecting encryption. | ✅ Completed |
| **FR-4** | Maintain a Sliding-Window aggregation queue for temporal event analysis. | ✅ Completed |
| **FR-5** | Track anomalous file extension renaming chains (e.g., `.locked`, `.crypto`). | ✅ Completed |
| **FR-6** | Execute isolated process monitoring and parent-child tree tracking. | ✅ Completed |
| **FR-7** | Compute a continuous Weighted Threat Score (0.0 – 100.0). | ✅ Completed |
| **FR-8** | Map Threat Scores to standardized severity bands (NORMAL, WARNING, CRITICAL). | ✅ Completed |
| **FR-9** | Execute isolated evidence quarantine upon CRITICAL threshold breach. | ✅ Completed |
| **FR-10** | Expose a fast, async REST API backend (FastAPI). | ✅ Completed |
| **FR-11** | Build a real-time, interactive SOC Web Dashboard (React/TypeScript). | ✅ Completed |
| **FR-12** | Persist high-volume event data safely to a relational database (PostgreSQL). | ✅ Completed |
| **FR-13** | Implement a Server-Sent Events (SSE) pipeline for sub-second UI updates. | ✅ Completed |

---

## 🛠️ Build Phases Completed

This project successfully traversed all 10 architectural build phases:
1.  **Project Setup & Architecture**
2.  **Telemetry & Filesystem Monitoring**
3.  **Threat Analysis Engine & Entropy Calculation**
4.  **Database & ORM Layer Initialization**
5.  **FastAPI Core & REST Endpoint Routing**
6.  **Server-Sent Events (SSE) Pipeline Integration**
7.  **React Frontend Skeleton & State Management**
8.  **Real-Time Dashboard UI/UX Design**
9.  **SOAR Incident Responder Engine**
10. **Containerization & Docker Deployment**

---

## 🚀 Quick Start

Ensure **Docker Desktop** is running, then boot the entire RDRS platform with a single command:

```bash
docker-compose up -d --build
```

Access the interfaces once booted:
*   🎨 **React SOC Dashboard**: `http://localhost:5173`
*   ⚡ **FastAPI REST API Docs**: `http://localhost:8000/docs`

To stop the environment:
```bash
docker-compose down -v
```

---

## ⚠️ Safety Notes & Educational Disclaimer

> [!WARNING]
> **Defensive Simulation Mode Only**
> 
> This tool is strictly engineered for **educational use** and operates in a "Defensive Simulation Mode." 
> *   **No Destructive Actions**: The SOAR Incident Responder (`responder.py`) does **not** execute destructive OS commands on the host machine.
> *   **Safe Evidence Handling**: When a threat is detected, `quarantine_evidence()` strictly uses secure copy operations (`shutil.copy2`); the original evidence files are never modified or deleted.
> *   **Simulated Process Kill**: The `simulate_neutralization()` method safely logs the intended termination of a target PID without invoking a true `os.kill` or `taskkill` against the host operating system.
