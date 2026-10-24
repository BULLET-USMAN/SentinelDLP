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

## 2. Implementation Status: Phase 5 Complete

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
- **[COMPLETED] Phase 5 — Intelligent Threat Risk Scoring, Detection Rules & Security Alert Engine**
  - **Deterministic Threat Scoring**: Normalized 0–100 risk score combining primary rule contributions and diminishing secondary rule weights, with soft capping at 100.
  - **Configurable Severity Bands**: `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–79), and `CRITICAL` (80–100).
  - **Core Philosophy**: **File sensitivity is context, not proof of malicious activity.** Ordinary modifications to sensitive assets remain in the LOW band unless supported by abnormal velocity, bulk operations, or structural alterations.
  - **8 Operational Detection Rules**:
    1. `RULE-SENS-MOD`: Sensitive File Modification (CONFIDENTIAL/RESTRICTED files).
    2. `RULE-RAPID-MOD`: Rapid File Modification Activity (high frequency of distinct files in 5 minutes).
    3. `RULE-BULK-RENAME`: Bulk File Renaming (high number of distinct renames; flags volume without asserting speculative conclusions).
    4. `RULE-SENS-DEL`: Sensitive File Deletion Activity (multiple classified deletions in 15 minutes, preserving historical classification).
    5. `RULE-REPEAT-CHANGE`: Repeated File Changes (high-churn alteration on a single path).
    6. `RULE-SENS-VOLUME`: Unusual Sensitive File Activity Volume (clustered operations on sensitive assets in 15 minutes).
    7. `RULE-EXT-CHANGE`: File Extension Change (tracks prior/new extension, applies bonus points for suspicious extensions like `.locked`, `.crypto`, `.enc`).
    8. `RULE-COVERAGE-WARN`: Monitoring Coverage Failure (queue overflow or dropped events; treated as a diagnostic visibility warning).
  - **Distinct Security Concepts**:
    - *Data Sensitivity*: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
    - *Threat Risk*: `0–100` score based on observable behavior in context.
    - *Evidence Completeness*: `COMPLETE`, `PARTIAL`, `INSUFFICIENT`.
    - *Detection Confidence*: `LOW`, `MEDIUM`, `HIGH`.
    - *Alert Severity*: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - **Alert Lifecycle & Sliding-Window Suppression**: Bounded 5-minute suppression window with repeat-counter tracking to prevent alert storms; supports `OPEN` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED` / `FALSE_POSITIVE` transitions with an immutable audit trail.
  - **Frontend Risk Intelligence Dashboard**: Dedicated operational view with risk distribution meters, sortable alerts table, and slide-out investigation drawer with analyst triage controls.
- **[PLANNED] Phase 6 — AI-Assisted Exfiltration Correlation, Incident Reconstruction & Investigation**

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
- **Design System**: Cybersecurity Dark Theme (`#0a0e17` background with `#10b981` emerald / `#f59e0b` amber / `#ef4444` red accents)

### Container Architecture
- **Multi-stage Docker** configurations running under non-root users (`sentinel` UID 1001, and `nginx` non-root user).
- **Internal service networking** and persistent named volumes.

---

## 4. Phase 5 Risk Scoring & Security Alert Architecture

```
┌────────────────────────────────────────────────────────┐
│         Normalized File Activity Event (Phase 4)       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│            Temporal Context Builder (DB-Backed)        │
│  - 5-min window: distinct modified files, renames      │
│  - 15-min window: sensitive deletions, sensitive vol   │
│  - Monitoring health: queue overflow & capture drops   │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           Security Detection Rules Evaluator           │
│  Evaluates 8 rules against event and temporal metrics  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           Deterministic Scoring Engine (0–100)         │
│  - Primary rule points + 0.6 * secondary rule points   │
│  - Capped at 100; maps to LOW, MEDIUM, HIGH, CRITICAL  │
│  - Evidence Completeness & Confidence assessment       │
│  - Human-readable explanation & SOC recommendations    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│          Alert Service & Suppression Engine            │
│  - Evaluates alerting thresholds (score >= 30)         │
│  - Deduplication key: hash(root + rule + file_path)    │
│  - 300s sliding-window suppression (increments repeat) │
│  - Triage lifecycle: OPEN -> ACK -> INVEST -> RESOLVED │
│  - Immutable audit trail (alert_audit_logs table)      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│       React Frontend: Risk Intelligence Dashboard      │
│  - Risk overview & severity breakdown tiles            │
│  - Filterable security alerts table                    │
│  - Slide-out alert investigation & triage drawer       │
│  - Detection rules catalog reference                   │
└────────────────────────────────────────────────────────┘
```

### Defensive Technical Boundaries
Filesystem observer telemetry indicates file creation, modification, deletion, and movement. It **does not** confirm process attribution, authenticated user credentials, memory access, or network exfiltration. SentinelDLP documents these boundaries truthfully in every assessment without fabricating telemetry.

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

### Risk Intelligence & Security Alerts (Phase 5)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/risk/assessments` | Paginated risk assessments with multi-parameter filtering |
| `GET` | `/api/v1/risk/assessments/{assessment_id}` | Complete assessment detail with granular rule matches and evidence |
| `GET` | `/api/v1/risk/statistics` | Aggregated risk metrics, score distribution, and average threat score |
| `GET` | `/api/v1/risk/rules` | Active detection rules catalog, thresholds, and template definitions |
| `GET` | `/api/v1/alerts` | Paginated security alerts with status and severity filters |
| `GET` | `/api/v1/alerts/{alert_id}` | Comprehensive alert detail with linked assessment and audit trail |
| `PATCH` | `/api/v1/alerts/{alert_id}/status` | Update alert triage lifecycle status with analyst commentary |
| `GET` | `/api/v1/alerts/statistics` | SOC triage metrics (counts by status: OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE) |

---

## 6. Database Schema & Migrations

Database schema management is handled via Alembic migrations:

1. `0001_initial_schema.py`: Base system configurations.
2. `0002_scan_jobs_and_files.py`: `scan_jobs` and `scanned_files` tables for Phase 2 file inventory.
3. `0003_classification_and_findings.py`: `file_classifications` and `detection_findings` tables for Phase 3 sensitive data discovery.
4. `0004_file_activity_monitoring.py`: `monitoring_configurations`, `file_activity_events`, and `monitoring_sessions` tables for Phase 4 real-time tracking.
5. `0005_risk_scoring_and_alerts.py`: `risk_assessments`, `rule_matches`, `security_alerts`, and `alert_audit_logs` tables for Phase 5 risk scoring and SOC triage.

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

Run the full pytest suite (78 tests across Phase 1, Phase 2, Phase 3, Phase 4, and Phase 5):

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

### Test Coverage Highlights:
- **Phase 2 Scanner**: Streaming SHA-256 chunking, magic-byte mismatch detection, directory traversal security, and cooperative cancellation tokens.
- **Phase 3 Detection Engine**: Luhn algorithm validation, Shannon entropy calculation, high-confidence secret masking, PDF/DOCX content extraction, and policy classification.
- **Phase 4 Monitoring**: Watchdog event normalization, path traversal blocking, 0.4s sliding-window debouncing, bounded queue saturation & overflow tracking, live session lifecycle, and SSE event streaming.
- **Phase 5 Risk Engine**: 0–100 score normalization, diminishing returns formula, 8 security detection rules evaluated individually and in combinations, alert deduplication and 300s sliding-window suppression, analyst triage lifecycle transitions, audit logging, and REST API validation.

---

## 9. Project Roadmap

- **[x] Phase 1: Project Foundation, Backend Architecture & Development Environment**
- **[x] Phase 2: Intelligent File Scanning Engine & File Inventory System**
- **[x] Phase 3: Advanced Sensitive Data Detection & Classification Engine**
- **[x] Phase 4: Real-Time File Activity Monitoring & Security Event Collection**
- **[x] Phase 5: Intelligent Threat Risk Scoring, Detection Rules & Security Alert Engine**
- **[ ] Phase 6: AI-Assisted Exfiltration Correlation, Incident Reconstruction & Response**
