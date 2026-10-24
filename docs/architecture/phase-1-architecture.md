# SentinelDLP — Phase 1 Architectural Design & Technical Summary

## 1. Overview & Defensive Mission

**SentinelDLP** (AI-Powered Data Loss Prevention & Exfiltration Detection Platform) is designed to safeguard sensitive organizational data across authorized endpoints. 

In defensive cybersecurity, software platforms must adhere to rigid engineering principles:
1. **Zero Trust & Defense in Depth**: Default-deny policies, strictly scoped permissions, and least-privilege configurations.
2. **Defensive Secrets Management**: Credential isolation, password sanitization in log outputs, and strict environment decoupling.
3. **Graceful Degradation**: Dual-tier health probes that report operational and degraded states transparently without disclosing stack traces or database internal architectures.

Phase 1 establishes the software engineering baseline, repository structure, application lifecycle, database migration engine, and container definitions without introducing unvalidated threat detection logic or fake alerts.

---

## 2. System Architecture

```
+-------------------------------------------------------------------------+
|                        Frontend (React + Vite)                          |
|  - Dark Cybersecurity Aesthetic (#0a0e17 / #10b981 accents)             |
|  - Real-time Health Probing (/health/live, /health/ready)               |
|  - Transparent Architectural Roadmap Display                            |
+------------------------------------+------------------------------------+
                                     |  HTTP / JSON (Port 5173 / 8000)
                                     v
+-------------------------------------------------------------------------+
|                     Backend (FastAPI Modular Core)                      |
|  - App Lifespan Management (Structured JSON Logging)                   |
|  - Restricted CORS Middleware                                           |
|  - Centralized Exception Sanitizer (Zero credential leakage)            |
|  - API Router v1 (/api/v1/health, /api/v1/detection [Placeholder])      |
|  - Top-level Probes: GET /health/live, GET /health/ready                |
+------------------------------------+------------------------------------+
                                     |  SQLAlchemy 2.0 / psycopg2-binary
                                     v
+-------------------------------------------------------------------------+
|                  Database Layer (PostgreSQL 16)                         |
|  - Alembic Schema Migrations (0001_initial_schema)                      |
|  - System Audit Records (Platform lifecycle events)                     |
|  - Connection Pool with Pre-Ping & Active Timeout Boundaries            |
+-------------------------------------------------------------------------+
```

---

## 3. Component Details

### 3.1 Backend Core (`backend/app/`)
- **`core/config.py`**: Pydantic `BaseSettings` object dynamically parsing environment variables with type coercion, CORS list assembly, and password sanitization (`get_sanitized_db_url()`).
- **`core/logging.py`**: Structured JSON formatter outputting UTC ISO-8601 timestamps, log level, event names, and component identifiers.
- **`core/exceptions.py`**: Centralized exception handlers capturing `SentinelException`, `RequestValidationError`, and unexpected exceptions, translating them to standard `{ "error": { "code", "message", "details" } }` structures without leaking stack traces.
- **`db/session.py`**: Thread-safe SQLAlchemy engine and session factory with connection timeout protections (`DB_TIMEOUT_SECONDS=5`) and lightweight `SELECT 1` readiness probes.
- **`services/health_service.py`**: Service boundary cleanly isolating dependency probes from web route serialization.
- **`api/v1/endpoints/placeholder_detection.py`**: Explicit, documented architectural placeholders returning `501 Not Implemented` for inactive detection hooks, adhering strictly to Phase 1 boundaries.

### 3.2 Database & Migrations (`backend/alembic/`)
- **Alembic Engine**: Dynamically imports database settings from `app.core.config.settings`, ensuring no database credentials reside in `.ini` files.
- **Initial Migration (`0001_initial_schema`)**: Creates `system_audit_records` for recording platform startup, migration, and maintenance events.

### 3.3 Frontend Client (`frontend/`)
- **React 18 + TypeScript + Vite**: Responsive application shell styled in restrained cybersecurity dark theme.
- **Diagnostic Engine**: Periodically polls `/health/live` and `/health/ready`, accurately displaying operational vs degraded states with real roundtrip latency metrics.
- **No Fabricated Telemetry**: Strictly avoids simulated security alerts or dummy incident charts prior to real detection engine implementation in Phase 2.

### 3.4 Container Infrastructure
- **`backend/Dockerfile`**: Multi-stage build using `python:3.12-slim`, non-root user `sentinel` (UID 1001), container healthcheck querying `/health/live`.
- **`frontend/Dockerfile`**: Multi-stage build compiling static Vite assets and serving via hardened, non-root `nginx:1.25-alpine`.
- **`docker-compose.yml`**: Bridges all services on an internal network (`sentinel-internal`), isolates PostgreSQL storage with a persistent named volume, and uses native healthcheck conditions (`depends_on: db: condition: service_healthy`).
