# SentinelDLP — AI-Powered Data Loss Prevention & Exfiltration Detection Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Alembic](https://img.shields.io/badge/Alembic-1.13-orange.svg)](https://alembic.sqlalchemy.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Project Overview

**SentinelDLP** is an enterprise-grade defensive cybersecurity platform designed to monitor authorized endpoint activity, classify and safeguard sensitive intellectual property, detect suspicious data exfiltration attempts, and provide AI-assisted security investigations for Security Operations Center (SOC) teams.

### Core Objectives
- **Defensive Data Loss Prevention (DLP)**: Prevent unauthorized leaks of sensitive corporate data (PII, credentials, proprietary source code).
- **Behavioral & Heuristic Exfiltration Detection**: Identify abnormal file movement, bulk clipboard transfers, and suspicious outbound data channels.
- **AI-Assisted Threat Investigation**: Provide structured risk analysis and contextual telemetry for incident responders.
- **Security-First Architecture**: Enforce zero hardcoded credentials, non-root containers, restricted CORS policies, and centralized exception sanitization.

---

## 2. Current Development Posture: Phase 1 Complete

> **IMPORTANT**: In adherence to the engineering roadmap, **Phase 1 (Foundation, Backend Architecture & Development Environment)** is complete. 
> Detection engines, file monitoring agents, and AI components are scheduled for subsequent phases and are currently represented as strict, inactive architectural placeholders. No simulated or fabricated security incidents are generated.

---

## 3. Technology Stack

### Backend
- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) (Asynchronous ASGI Web Framework)
- **Validation & Settings**: [Pydantic v2](https://docs.pydantic.dev/) & [Pydantic-Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- **ORM & Database Driver**: [SQLAlchemy 2.0](https://www.sqlalchemy.org/) & [psycopg2-binary](https://www.psycopg.org/)
- **Database Migrations**: [Alembic](https://alembic.sqlalchemy.org/)
- **Server**: [Uvicorn](https://www.uvicorn.org/) (High-performance ASGI server)
- **Relational Datastore**: PostgreSQL 16

### Frontend
- **Library**: [React 18](https://react.dev/)
- **Language**: [TypeScript 5.4](https://www.typescriptlang.org/)
- **Build Tool**: [Vite 5](https://vitejs.dev/)
- **Styling**: Cybersecurity Dark Theme with subtle green accents (`#10b981`)

### Infrastructure & Tooling
- **Containerization**: Multi-stage Docker & Docker Compose
- **Testing**: Pytest & FastAPI TestClient / HTTPX

---

## 4. Repository Architecture

```text
SentinelDLP/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   ├── health.py               # Liveness & readiness endpoints
│   │   │       │   └── placeholder_detection.py# Explicit Phase 2+ placeholders
│   │   │       └── router.py                   # Central API v1 router
│   │   ├── core/
│   │   │   ├── config.py                       # Pydantic Settings & credential masking
│   │   │   ├── exceptions.py                   # Centralized error sanitization
│   │   │   └── logging.py                      # Structured JSON logging
│   │   ├── db/
│   │   │   ├── base.py                         # SQLAlchemy declarative base
│   │   │   └── session.py                      # Engine & database probe
│   │   ├── models/
│   │   │   └── system.py                       # Baseline system audit records
│   │   ├── schemas/
│   │   │   └── health.py                       # Request/response validation schemas
│   │   ├── services/
│   │   │   └── health_service.py               # Health verification logic
│   │   └── main.py                             # FastAPI entry point & lifespan
│   ├── alembic/
│   │   ├── versions/
│   │   │   └── 0001_initial_schema.py          # Initial database migration
│   │   └── env.py                              # Dynamic Alembic environment
│   ├── tests/
│   │   ├── conftest.py                         # Test fixtures & TestClient
│   │   ├── test_config.py                      # Settings & masking tests
│   │   ├── test_errors.py                      # Error handling & status tests
│   │   └── test_health.py                      # Mocked & live health tests
│   ├── Dockerfile                              # Multi-stage non-root container
│   ├── alembic.ini                             # Migration configuration
│   └── requirements.txt                        # Backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx                      # Cybersecurity application shell
│   │   │   └── StatusCard.tsx                  # System status metric card
│   │   ├── pages/
│   │   │   ├── SystemStatusPage.tsx            # Live health & dependency monitor
│   │   │   └── DocumentationPage.tsx           # Architecture & roadmap viewer
│   │   ├── services/
│   │   │   └── api.ts                          # Real health API client
│   │   ├── types/
│   │   │   └── health.ts                       # TypeScript interfaces
│   │   ├── App.tsx                             # Shell controller
│   │   ├── index.css                           # Dark theme styles
│   │   └── main.tsx                            # React entry point
│   ├── Dockerfile                              # Hardened Nginx container
│   ├── nginx.conf                              # Nginx reverse proxy & headers
│   ├── package.json                            # Frontend dependencies
│   ├── tsconfig.json                           # TypeScript configuration
│   └── vite.config.ts                          # Vite build & proxy settings
├── docs/
│   ├── architecture/
│   │   └── phase-1-architecture.md             # Detailed technical architecture
│   └── development/
│       ├── setup-windows.md                    # Windows 11 setup guide
│       └── testing-guide.md                    # Automated testing guide
├── scripts/
│   ├── run_local.ps1                           # One-click Windows dev runner
│   ├── test_backend.ps1                        # Pytest automation runner
│   └── migrate.ps1                             # Alembic migration utility
├── docker-compose.yml                          # Container orchestration
├── .env.example                                # Configuration template (no credentials)
├── .gitignore                                  # Comprehensive Git exclusions
└── README.md
```

---

## 5. Quick Start (Windows 11)

### 5.1 Prerequisites
- Python 3.11+ (Python 3.12 recommended)
- Node.js 18+ and npm
- Git

### 5.2 Environment Configuration
Copy the configuration template to `.env`:
```powershell
Copy-Item .env.example .env
```

### 5.3 Backend Setup
```powershell
# Create virtual environment
python -m venv .venv

# Install dependencies
.\.venv\Scripts\pip.exe install -r backend\requirements.txt

# Run automated tests
.\.venv\Scripts\python.exe -m pytest -v backend\tests

# Start backend server
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000 --host 127.0.0.1 --reload
```
- API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Liveness Probe: [http://127.0.0.1:8000/health/live](http://127.0.0.1:8000/health/live)
- Readiness Probe: [http://127.0.0.1:8000/health/ready](http://127.0.0.1:8000/health/ready)

### 5.4 Frontend Setup
```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```
- Frontend UI: [http://localhost:5173](http://localhost:5173)

---

## 6. Docker Deployment

When Docker and Docker Compose are installed:

```powershell
# Build and start all services
docker compose up --build -d

# View container logs
docker compose logs -f backend

# Stop services
docker compose down
```

### Container Security Features
- **Non-Root Execution**: Backend runs under UID 1001 (`sentinel`); Frontend runs under `nginx` non-root user.
- **Port Isolation**: PostgreSQL is bound strictly to `127.0.0.1` and internal Docker networks.
- **Container Healthchecks**: Automatic health validation before depending services start.

---

## 7. Running Automated Tests

Run the full pytest suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

Or using the helper script:
```powershell
.\scripts\test_backend.ps1
```

All 12 unit and endpoint tests run in <0.2 seconds, covering:
1. Application initialization and root metadata.
2. Root and versioned `/health/live` probes.
3. Database readiness when operational (mocked).
4. Database readiness when unavailable (503 Service Unavailable, mocked).
5. Settings parsing and credential masking in connection strings.
6. Error handling and placeholder endpoint rejection (501 Not Implemented).

---

## 8. Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `PSSecurityException` running `npm` | Windows PowerShell execution policy | Run `npm.cmd` directly or configure `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `/health/ready` returns HTTP 503 | PostgreSQL is not currently running | Expected during standalone backend runs without a local DB. Start Postgres or Docker Compose. |
| Port 8000 or 5173 already in use | Previous process still bound to port | Run `Get-NetTCPConnection -LocalPort 8000` and stop the conflicting PID. |

---

## 9. Development Roadmap

- **[COMPLETED] Phase 1: Project Foundation & Architecture**
  - Modular monorepo, FastAPI backend, SQLAlchemy/Alembic, React/TS frontend, Docker Compose, structured JSON logging, zero-secret hygiene.
- **[NEXT] Phase 2: Core Detection Engine**
  - Sensitive file classification (Regex, entropy, keyword matching), file hash calculation, pattern matching.
- **[FUTURE] Phase 3: Exfiltration Heuristics**
  - Endpoint monitoring, volume anomaly detection, suspicious USB/cloud transfer heuristic indicators.
- **[FUTURE] Phase 4: AI Security Assistant**
  - Contextual LLM analysis, automated threat summarization, guided remediation workflows.
