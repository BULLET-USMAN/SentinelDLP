# SentinelDLP — AI-Powered Data Loss Prevention & Exfiltration Detection Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Alembic](https://img.shields.io/badge/Alembic-1.20-orange.svg)](https://alembic.sqlalchemy.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

---

## 1. Project Overview

**SentinelDLP** is an enterprise-grade defensive cybersecurity platform designed to monitor authorized endpoint activity, discover and inventory corporate data assets, identify sensitive intellectual property, detect suspicious data exfiltration attempts, and provide AI-assisted security investigations for SOC teams.

Designed with modular, defense-in-depth principles, SentinelDLP emphasizes zero-leakage security, explicit authorization boundaries, accurate telemetry attribution, and robust test-driven engineering.

---

## 2. Implementation Status: Phase 4 Complete

- **[COMPLETED] Phase 1 — Project Foundation & Architecture**
  - Robust FastAPI asynchronous backend, SQLAlchemy 2.0 ORM, and Alembic database migrations.
  - React 18 + TypeScript + Vite frontend with dark cybersecurity operations dashboard.
  - PostgreSQL 16 relational database with health probes and Docker Compose integration.
- **[COMPLETED] Phase 2 — Intelligent File Scanning Engine & Inventory System**
  - Path traversal and symlink escape defenses verifying authorized directories.
  - Streaming SHA-256 cryptographic hashing (64 KB chunking).
  - Multi-category file identification across Documents, Code, Config, Images, and Archives.
  - Magic byte inspection and extension mismatch detection (`type_mismatch` flag).
  - Asynchronous scan worker with non-blocking cooperative cancellation tokens.
- **[COMPLETED] Phase 3 — Sensitive Data Detection & Classification Engine**
  - Content extractors for plain text, source code, configs, PDF, and DOCX documents.
  - Comprehensive sensitive pattern detectors: PCI-DSS Payment Cards (with Luhn checksum validation), US SSNs, AWS Access Keys, GitHub PATs, Generic API Keys & Bearer Tokens (Shannon entropy analysis), Private Keys (RSA/EC/OpenSSH), and Corporate Confidential Markers.
  - Explainable classification tiers: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
  - Zero-leakage redaction: sensitive findings are strictly masked (e.g. `4532-••••-••••-1111`) before database persistence and display.
- **[COMPLETED] Phase 4 — Real-Time File Activity Monitoring & Security Event Collection**
  - Continuous filesystem monitoring across authorized scan roots using Python `watchdog`.
  - Real-time observation of file and directory creations, modifications, deletions, renames, and moves.
  - Deduplication and debouncing engine (0.4s sliding window) suppressing multi-event save storms.
  - Thread-safe bounded event queue (5,000 max size) with non-blocking ingestion and queue overflow telemetry.
  - Background event worker automatically performing Phase 2 metadata extraction/hashing and Phase 3 sensitive content inspection on modified/created files.
  - Server-Sent Events (SSE) streaming endpoint (`/api/v1/monitoring/events/stream`) providing sub-second frontend updates.
  - Live Activity operational UI with live telemetry counters, start/stop session controls, live event feed, and zero-leakage event audit drawer.
  - Strict attribution transparency: Filesystem events record `event_source="watchdog"` and do not fabricate user or process attribution.
- **[PLANNED] Phase 5 — Behavioral Risk Scoring & Anomaly Detection**
- **[PLANNED] Phase 6 — AI-Assisted Exfiltration Correlation & Incident Investigation**

---

## 3. Technology Stack

### Backend
- **Framework**: FastAPI (Asynchronous Web API)
- **Settings & Validation**: Pydantic v2 & Pydantic-Settings
- **ORM & Migrations**: SQLAlchemy 2.0 & Alembic
- **Database**: PostgreSQL 16 (Alpine)
- **Filesystem Monitoring**: Watchdog 4.0
- **Document Parsing**: PyPDF & python-docx
- **Server**: Uvicorn ASGI

### Frontend
- **Framework**: React 18 & TypeScript 5.4
- **Tooling**: Vite 5
- **Icons**: Lucide React
- **Design System**: Cybersecurity Dark Theme (`#0a0e17` background with `#10b981` emerald / `#3b82f6` blue accents)

### Container Architecture
- **Multi-stage Docker** configurations running under non-root users (`sentinel` UID 1001, and `nginx` non-root user).
- **Internal service networking** and persistent named volumes.

---

## 4. Phase 4 Monitoring Architecture & Data Flow

```
┌────────────────────────────────────────────────────────┐
│             Authorized Directory Filesystem             │
└───────────────────────────┬────────────────────────────┘
                            │ OS filesystem notifications
                            ▼
┌────────────────────────────────────────────────────────┐
│            Python Watchdog (FileObserver)              │
│       Captures: CREATE, MODIFY, DELETE, MOVE, RENAME   │
└───────────────────────────┬────────────────────────────┘
                            │ Raw filesystem events
                            ▼
┌────────────────────────────────────────────────────────┐
│           EventNormalizer & Boundary Check             │
│  - Standardizes paths relative to authorized root      │
│  - Blocks path traversal & directory escapes           │
│  - Classifies moves (INTERNAL, INBOUND, OUTBOUND)      │
└───────────────────────────┬────────────────────────────┘
                            │ Normalized events
                            ▼
┌────────────────────────────────────────────────────────┐
│          EventDebouncer (Sliding Window: 0.4s)         │
│  - Suppresses write/flush storms on single file        │
│  - Preserves structural changes (CREATE/DELETE/RENAME) │
└───────────────────────────┬────────────────────────────┘
                            │ Debounced events
                            ▼
┌────────────────────────────────────────────────────────┐
│          Bounded Event Queue (Capacity: 5000)          │
│  - Non-blocking ingestion prevents filesystem blocking │
│  - Tracks queue overflows and drops cleanly on surge   │
└───────────────────────────┬────────────────────────────┘
                            │ Ingestion worker
                            ▼
┌────────────────────────────────────────────────────────┐
│         Async EventProcessor (Background Worker)       │
│  - Phase 2 Integration: Updates size, mod_time, SHA256 │
│  - Phase 3 Integration: Triggers sensitive data scans  │
│  - DB Persistence: file_activity_events table          │
│  - Broadcast: Server-Sent Events (SSE) channel         │
└───────────────────────────┬────────────────────────────┘
                            │ Real-time SSE Stream
                            ▼
┌────────────────────────────────────────────────────────┐
│        React Frontend: Live Activity Dashboard         │
│  - Real-time KPI tiles & session controls              │
│  - Auto-updating live activity feed & filter controls  │
│  - Zero-leakage event audit drawer                     │
└────────────────────────────────────────────────────────┘
```

### Important Defensive Technical Reality
Filesystem notifications provided by OS-level watchers (Windows ReadDirectoryChangesW, Linux inotify) capture filesystem state transitions, but **do not** reliably expose user credentials or originating process IDs without kernel drivers (ETW / eBPF). In adherence to professional cybersecurity engineering ethics, SentinelDLP records `event_source="watchdog"` and leaves process and user attribution strictly un-fabricated.

---

## 5. API Endpoints Reference

### Health Probes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health/live` | Application process liveness probe |
| `GET` | `/health/ready` | Dependency readiness probe (PostgreSQL database connectivity) |

### Scanner & Inventory (Phase 2 & Phase 3)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/scanner/roots` | List administrator-configured authorized scan roots |
| `POST` | `/api/v1/scans` | Start background file scan job on an authorized root |
| `GET` | `/api/v1/scans` | List historical scan runs |
| `GET` | `/api/v1/scans/{scan_id}` | Get status and metrics of a scan job |
| `GET` | `/api/v1/scans/{scan_id}/files` | Paginated file inventory with search, mismatch & sensitivity filters |
| `POST` | `/api/v1/scans/{scan_id}/cancel` | Cancel an ongoing scan job |
| `GET` | `/api/v1/scans/{scan_id}/files/{file_id}/findings` | Retrieve explainable sensitive data detection findings for a file |

### Real-Time Activity Monitoring (Phase 4)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/monitoring/roots` | List authorized roots available for real-time monitoring |
| `GET` | `/api/v1/monitoring/status` | Current active monitoring sessions and watcher status |
| `POST` | `/api/v1/monitoring/start` | Start real-time monitoring observer on an authorized root |
| `POST` | `/api/v1/monitoring/stop` | Stop monitoring session on an authorized root |
| `GET` | `/api/v1/monitoring/events` | Paginated query of captured file activity events with filters |
| `GET` | `/api/v1/monitoring/events/{event_id}` | Detailed event inspection record |
| `GET` | `/api/v1/monitoring/statistics` | Aggregated telemetry (total events, deduplicated, queue overflows) |
| `GET` | `/api/v1/monitoring/events/stream` | Server-Sent Events (SSE) real-time event stream for dashboards |

---

## 6. Database Schema & Migrations

Database schema management is handled via Alembic migrations:

1. `0001_initial_schema.py`: Base system configurations.
2. `0002_scan_jobs_and_files.py`: `scan_jobs` and `scanned_files` tables for Phase 2 file inventory.
3. `0003_classification_and_findings.py`: `file_classifications` and `detection_findings` tables for Phase 3 sensitive data discovery.
4. `0004_file_activity_monitoring.py`: `monitoring_configurations`, `file_activity_events`, and `monitoring_sessions` tables for Phase 4 real-time tracking.

---

## 7. Quick Start (Windows 11 & Docker)

### Option A: Docker Compose (Full Stack)
```powershell
# Build and start all services in detached mode
docker compose up --build -d

# Check service health
docker compose ps
```
- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)
- **API Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Monitor**: [http://localhost:8000/health/ready](http://localhost:8000/health/ready)

### Option B: Local Python & Node Execution
```powershell
# 1. Activate Python virtual environment and install dependencies
.\.venv\Scripts\activate
pip install -r backend\requirements.txt

# 2. Run database migrations
cd backend
alembic upgrade head
cd ..

# 3. Start Backend API
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000 --host 127.0.0.1 --reload

# 4. In a separate terminal, start Frontend
cd frontend
npm.cmd install
npm.cmd run dev
```

---

## 8. Automated Test Suite

SentinelDLP maintains a comprehensive automated test suite spanning unit tests, integration tests, boundary verifications, and cryptographic vectors.

Run the full pytest suite (61 tests across Phase 1, Phase 2, Phase 3, and Phase 4):

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

### Test Coverage Highlights:
- **Phase 2 Scanner**: Streaming SHA-256 chunking, magic-byte mismatch detection, directory traversal security, and cooperative cancellation tokens.
- **Phase 3 Detection Engine**: Luhn algorithm validation, Shannon entropy calculation, high-confidence secret masking, PDF/DOCX content extraction, and policy classification.
- **Phase 4 Monitoring**: Watchdog event normalization, path traversal blocking, 0.4s sliding-window debouncing, bounded queue saturation & overflow tracking, live session lifecycle, and SSE event streaming.

---

## 9. Project Roadmap

- **[x] Phase 1: Project Foundation, Backend Architecture & Development Environment**
- **[x] Phase 2: Intelligent File Scanning Engine & File Inventory System**
- **[x] Phase 3: Advanced Sensitive Data Detection & Classification Engine**
- **[x] Phase 4: Real-Time File Activity Monitoring & Security Event Collection**
- **[ ] Phase 5: Behavioral Risk Scoring, Anomaly Detection & Threat Heuristics**
- **[ ] Phase 6: AI-Assisted Exfiltration Correlation, Incident Reconstruction & Response**
