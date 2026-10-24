# Testing Guide for SentinelDLP

This guide covers the testing methodology, test categorization, and execution instructions.

---

## 1. Test Architecture

The SentinelDLP test suite adheres strictly to security engineering best practices:
- **Zero Secret Exposure**: Verifies that passwords in connection strings are masked before logging or response formatting.
- **Mocked Dependency Probes**: Uses `unittest.mock.patch` to simulate database availability and database outages deterministically, guaranteeing tests run reliably in CI/CD without requiring a live PostgreSQL instance.
- **HTTP Contract Validation**: Validates HTTP status codes (200 OK, 404 Not Found, 422 Unprocessable Entity, 501 Not Implemented, 503 Service Unavailable).

---

## 2. Test Catalog

| Test File | Target | Description |
|---|---|---|
| `test_health.py` | `test_app_initialization` | Verifies root `/` metadata initialization |
| `test_health.py` | `test_liveness_endpoint_root` | Verifies `GET /health/live` returns 200 OK and valid JSON |
| `test_health.py` | `test_liveness_endpoint_v1` | Verifies `GET /api/v1/health/live` route compatibility |
| `test_health.py` | `test_readiness_endpoint_when_database_available` | **[Mocked Unit Test]** Verifies `GET /health/ready` returns 200 OK and database `up` |
| `test_health.py` | `test_readiness_endpoint_when_database_unavailable` | **[Mocked Unit Test]** Verifies `GET /health/ready` returns 503 SERVICE UNAVAILABLE and database `down` |
| `test_health.py` | `test_readiness_endpoint_v1_router_when_healthy` | **[Mocked Unit Test]** Verifies `GET /api/v1/health/ready` versioned routing |
| `test_config.py` | `test_settings_defaults` | Validates default timeout and configuration values |
| `test_config.py` | `test_cors_origins_parsing` | Validates parsing comma-delimited strings into origin lists |
| `test_config.py` | `test_database_url_credential_masking` | Verifies passwords are never output by `get_sanitized_db_url()` |
| `test_errors.py` | `test_404_not_found` | Validates clean JSON handling of missing routes |
| `test_errors.py` | `test_placeholder_endpoint_returns_501_not_implemented` | Verifies Phase 1 detection hooks refuse execution with 501 Not Implemented |
| `test_errors.py` | `test_detection_status_roadmap_info` | Verifies roadmap status reports Phase 1 foundation posture |

---

## 3. Running the Tests

Execute via the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

Or execute via the PowerShell script:

```powershell
.\scripts\test_backend.ps1
```
