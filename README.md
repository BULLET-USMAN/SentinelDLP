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

---

## 2. Current Posture: Phase 2 Complete

- **Phase 1 (Foundation & Infrastructure)**: Completed & Verified.
- **Phase 2 (Intelligent File Scanner & Inventory System)**: Completed & Verified.
  - Secure directory discovery with traversal and symlink escape defenses.
  - Streaming SHA-256 cryptographic hashing (64KB buffer).
  - File type classification across Documents, Structured Data, Code, Config, Images, and Archives.
  - Extension vs content-signature (magic bytes) discrepancy detection (`type_mismatch` flag).
  - Background asynchronous execution worker with real-time cancellation tokens.
  - PostgreSQL persistence (`scan_jobs` and `scanned_files` tables via Alembic).
  - React/TypeScript operational dashboard with real-time statistics, search, filtering, and copyable hashes.

> **Scope Note**: In adherence to Phase 2 boundaries, content extraction, pattern-matching inspection, and AI analysis are reserved for subsequent phases. No fake alerts are generated.

---

## 3. Technology Stack

### Backend
- **Framework**: FastAPI (Asynchronous Web API)
- **Settings & Validation**: Pydantic v2 & Pydantic-Settings
- **ORM & Migrations**: SQLAlchemy 2.0 & Alembic
- **Database**: PostgreSQL 16 (Alpine)
- **Server**: Uvicorn ASGI

### Frontend
- **Framework**: React 18 & TypeScript 5.4
- **Tooling**: Vite 5
- **Design**: Professional Cybersecurity Dark Theme (`#0a0e17` / `#10b981` accents)

### Container Architecture
- **Multi-stage Docker** configurations running under non-root users (`sentinel` UID 1001, and `nginx` non-root user).
- **Internal service networking** and persistent named volumes.

---

## 4. API Endpoints

### Health & Monitoring
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health/live` | Application process liveness probe |
| `GET` | `/health/ready` | Dependency readiness probe (PostgreSQL connectivity) |

### Scanner & Inventory (Phase 2)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/scanner/roots` | List administrator-configured authorized scan roots |
| `POST` | `/api/v1/scans` | Start background file scan job on an authorized root |
| `GET` | `/api/v1/scans` | List historical scan runs |
| `GET` | `/api/v1/scans/{scan_id}` | Get status and metrics of a scan job |
| `GET` | `/api/v1/scans/{scan_id}/files` | Paginated file inventory with search & mismatch filter |
| `POST` | `/api/v1/scans/{scan_id}/cancel` | Cancel an ongoing scan job |

---

## 5. Quick Start (Windows 11 & Docker)

### Option A: Docker Compose (Recommended)
```powershell
# Build and run complete stack
docker compose up --build -d

# Check service health
docker compose ps
```
- **File Scanner Dashboard**: [http://localhost:5173](http://localhost:5173)
- **API Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Monitor**: [http://localhost:8000/health/ready](http://localhost:8000/health/ready)

### Option B: Local Python & Node Execution
```powershell
# Backend
python -m venv .venv
.\.venv\Scripts\pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000 --host 127.0.0.1 --reload

# Frontend
cd frontend
npm.cmd install
npm.cmd run dev
```

---

## 6. Running Automated Tests

Run the full pytest suite (29 tests):

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

Or using the helper script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_backend.ps1
```

All 29 tests validate:
- Known SHA-256 cryptographic test vectors and memory streaming chunking.
- Detection of all supported file types and magic number discrepancies.
- Security boundary enforcement (traversal and symlink escape attempts).
- Real-time cancellation tokens.
- End-to-end scan lifecycle, database persistence, pagination, and mismatch filtering.

---

## 7. Roadmap

- **[COMPLETED] Phase 1: Project Foundation & Architecture**
- **[COMPLETED] Phase 2: Intelligent File Scanning Engine & Inventory System**
- **[PLANNED] Phase 3: Content Inspection & Sensitive Data Classification**
  - Regular expression patterns (PII, credentials, API keys), high-entropy token detection, custom rule engine.
- **[PLANNED] Phase 4: Exfiltration Heuristics & Behavioral Monitoring**
- **[PLANNED] Phase 5: AI-Assisted Security Investigation**
