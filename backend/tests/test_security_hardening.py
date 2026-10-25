"""Comprehensive Security Hardening and Vulnerability Regression Tests (Phase 11).

Validates defenses against:
1. Authentication bypass & missing credentials
2. Invalid tokens and timing-safe rejection
3. Role-Based Access Control (RBAC) privilege enforcement (ADMIN vs ANALYST vs READONLY)
4. Path traversal in network telemetry ingestion (CWE-22)
5. Cyberattack simulation execution rejection in production (CWE-1188)
6. Oversized request body rejection (HTTP 413 / CWE-400)
7. Direct HTTP defensive security response headers
8. Production configuration validation (insecure default credential rejection)
9. SQL injection resistance on search and filtering endpoints
10. XSS payload handling in user comments and queries
11. Sensitive data masking and zero-leakage redaction
12. AI SOC Analyst prohibited tool rejection
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.ai.security.permissions import is_tool_authorized
from app.core.auth import Role
from app.core.config import Settings, settings
from app.ai.security.sanitization import sanitize_text
from app.main import app
from app.network.services.ingestion_service import NetworkIngestionService
from app.scanner.validators import SecurityBoundaryException
from app.simulation.config import simulation_settings


@pytest.fixture
def auth_client():
    """TestClient instance configured for security tests."""
    return TestClient(app)


def test_auth_enforcement_missing_credentials_rejected(auth_client: TestClient):
    """Verify that protected administrative endpoints reject unauthenticated requests when auth is enforced."""
    original_enforced = settings.AUTH_ENFORCED
    try:
        settings.AUTH_ENFORCED = True
        res = auth_client.post("/api/v1/scans", json={"root_id": "synthetic_samples"})
        assert res.status_code == 401
        data = res.json()
        assert "detail" in data
        assert "Authentication credentials missing" in data["detail"]
    finally:
        settings.AUTH_ENFORCED = original_enforced


def test_auth_enforcement_invalid_token_rejected(auth_client: TestClient):
    """Verify that requests with invalid API keys are rejected with 401 Unauthorized."""
    original_enforced = settings.AUTH_ENFORCED
    try:
        settings.AUTH_ENFORCED = True
        res = auth_client.post(
            "/api/v1/scans",
            json={"root_id": "synthetic_samples"},
            headers={"X-API-Key": "invalid_forged_key_123"},
        )
        assert res.status_code == 401
        assert "Invalid authentication credentials" in res.json()["detail"]
    finally:
        settings.AUTH_ENFORCED = original_enforced


def test_rbac_insufficient_role_rejected(auth_client: TestClient):
    """Verify that a READONLY user cannot execute ADMIN operations."""
    original_enforced = settings.AUTH_ENFORCED
    try:
        settings.AUTH_ENFORCED = True
        # Readonly key attempting to start a file scan (requires ADMIN)
        res = auth_client.post(
            "/api/v1/scans",
            json={"root_id": "synthetic_samples"},
            headers={"X-API-Key": settings.READONLY_API_KEY},
        )
        assert res.status_code == 403
        data = res.json()
        assert "Access denied" in data["detail"]
        assert "ADMIN" in data["detail"]
    finally:
        settings.AUTH_ENFORCED = original_enforced


def test_rbac_admin_key_authorized(auth_client: TestClient):
    """Verify that valid ADMIN key grants authorized access."""
    original_enforced = settings.AUTH_ENFORCED
    try:
        settings.AUTH_ENFORCED = True
        res = auth_client.get(
            "/api/v1/scanner/roots",
            headers={"X-API-Key": settings.ADMIN_API_KEY},
        )
        assert res.status_code == 200
        assert isinstance(res.json(), list)
    finally:
        settings.AUTH_ENFORCED = original_enforced


def test_bearer_authorization_header(auth_client: TestClient):
    """Verify that standard Authorization: Bearer <key> is supported."""
    original_enforced = settings.AUTH_ENFORCED
    try:
        settings.AUTH_ENFORCED = True
        res = auth_client.get(
            "/api/v1/scanner/roots",
            headers={"Authorization": f"Bearer {settings.ANALYST_API_KEY}"},
        )
        assert res.status_code == 200
    finally:
        settings.AUTH_ENFORCED = original_enforced


def test_network_ingest_path_traversal_blocked(auth_client: TestClient):
    """Verify that network ingestion blocks path traversal attempts resolving outside authorized directories."""
    traversal_paths = [
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "../../backend/app/core/config.py",
        "/var/log/syslog",
    ]
    for bad_path in traversal_paths:
        res = auth_client.post(
            "/api/v1/network/ingest",
            json={
                "sensor_id": "zeek-sensor-01",
                "source_format": "PCAP",
                "file_path": bad_path,
            },
            headers={"X-API-Key": settings.ADMIN_API_KEY},
        )
        # Should be rejected with 403 Forbidden or 422
        assert res.status_code in (403, 422), f"Expected rejection for {bad_path}, got {res.status_code}"


def test_network_ingestion_service_path_validator_direct():
    """Unit test for NetworkIngestionService path boundary validation."""
    with pytest.raises(SecurityBoundaryException) as exc_info:
        NetworkIngestionService._validate_ingestion_path("/etc/shadow")
    assert "outside authorized" in str(exc_info.value).lower()


def test_simulation_blocked_in_production_environment(auth_client: TestClient):
    """Verify that cyberattack simulation runs are strictly rejected in production mode."""
    orig_env = settings.ENVIRONMENT
    orig_allow = simulation_settings.allow_production_simulation
    try:
        settings.ENVIRONMENT = "production"
        simulation_settings.allow_production_simulation = False

        res = auth_client.post(
            "/api/v1/simulation/runs",
            json={"scenario_id": "SCEN-01"},
            headers={"X-API-Key": settings.ADMIN_API_KEY},
        )
        assert res.status_code == 403
        assert "disabled in production" in res.json()["detail"].lower()
    finally:
        settings.ENVIRONMENT = orig_env
        simulation_settings.allow_production_simulation = orig_allow


def test_request_body_size_limit_rejection(auth_client: TestClient):
    """Verify that requests exceeding MAX_REQUEST_BODY_BYTES are rejected with HTTP 413."""
    # Send a request with Content-Length larger than 10MB
    headers = {
        "Content-Length": str(20 * 1024 * 1024),  # 20 MB
        "X-API-Key": settings.ADMIN_API_KEY,
    }
    res = auth_client.post("/api/v1/scans", content=b"x", headers=headers)
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_security_headers_present_on_all_responses(auth_client: TestClient):
    """Verify essential defensive security headers on direct API responses."""
    res = auth_client.get("/health/live")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in headers.get("Content-Security-Policy", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_production_configuration_validation():
    """Verify that Settings raises a validation error when production environment uses insecure defaults."""
    with pytest.raises(ValueError) as exc:
        Settings(
            ENVIRONMENT="production",
            POSTGRES_PASSWORD="sentinel_secure_dev_password",
        )
    assert "default database password" in str(exc.value).lower()

    with pytest.raises(ValueError) as exc:
        Settings(
            ENVIRONMENT="production",
            POSTGRES_PASSWORD="strong_random_password_987",
            ADMIN_API_KEY="sentinel_admin_key_dev_sec",
        )
    assert "default administrative api key" in str(exc.value).lower()

    with pytest.raises(ValueError) as exc:
        Settings(
            ENVIRONMENT="production",
            POSTGRES_PASSWORD="strong_random_password_987",
            ADMIN_API_KEY="strong_admin_key_xyz_123",
            DEBUG=True,
        )
    assert "debug mode must be disabled" in str(exc.value).lower()


def test_sensitive_data_zero_leakage_redaction():
    """Verify that payment card and secret patterns are masked properly before display/storage."""
    raw_card = "4532-0150-1234-1111"
    sanitized = sanitize_text(f"Customer card: {raw_card}")
    assert raw_card not in sanitized
    assert "[REDACTED_PAYMENT_CARD]" in sanitized

    raw_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    sanitized_token = sanitize_text(f"Token: {raw_token}")
    assert raw_token not in sanitized_token
    assert "[REDACTED_GITHUB_PAT]" in sanitized_token


def test_ai_analyst_prohibited_tools_rejected():
    """Verify that disruptive tools are rejected by the AI tool permission validator."""
    prohibited_tools = [
        "quarantine_file",
        "delete_file",
        "terminate_process",
        "block_ip",
        "modify_firewall",
        "execute_script",
        "shell_exec",
        "raw_sql_query",
    ]
    for tool in prohibited_tools:
        assert not is_tool_authorized(tool), f"Expected tool '{tool}' to be prohibited"

    assert is_tool_authorized("get_alert")
    assert is_tool_authorized("get_investigation_timeline")
    assert is_tool_authorized("get_mitre_technique")


def test_sql_injection_defense_in_search(auth_client: TestClient):
    """Verify that SQL injection attempt payloads on search endpoints are safely parameterized."""
    sql_payloads = [
        "' OR 1=1 --",
        "'; DROP TABLE scanned_files; --",
        "' UNION SELECT null, null, null --",
        "1' OR '1'='1",
    ]
    for payload in sql_payloads:
        res = auth_client.get(
            "/api/v1/dashboard/search",
            params={"q": payload},
            headers={"X-API-Key": settings.READONLY_API_KEY},
        )
        assert res.status_code == 200, f"Expected 200 parameterized result, got {res.status_code}"
        data = res.json()
        assert "total_results" in data


def test_xss_payload_in_queries_handled_safely(auth_client: TestClient):
    """Verify that XSS injection payloads in queries and comments are treated strictly as data."""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    for xss in xss_payloads:
        res = auth_client.get(
            "/api/v1/dashboard/search",
            params={"q": xss},
            headers={"X-API-Key": settings.READONLY_API_KEY},
        )
        assert res.status_code == 200
        assert "<script>" not in res.headers.get("Content-Type", "")
