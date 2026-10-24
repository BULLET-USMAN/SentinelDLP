"""Health and Readiness Endpoint Tests for SentinelDLP.

Tests both process liveness and dependency readiness in healthy and degraded states.
Clearly distinguishes between mocked unit tests and real integration probes.
"""

from unittest.mock import patch
from fastapi.testclient import TestClient


def test_app_initialization(client: TestClient) -> None:
    """Verify application root metadata endpoint initializes properly."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SentinelDLP"
    assert "version" in data
    assert data["status"] == "operational"


def test_liveness_endpoint_root(client: TestClient) -> None:
    """Verify root GET /health/live returns healthy process status."""
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "live"
    assert data["app_name"] == "SentinelDLP"
    assert "timestamp" in data
    assert "version" in data


def test_liveness_endpoint_v1(client: TestClient) -> None:
    """Verify versioned GET /api/v1/health/live returns healthy process status."""
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "live"
    assert data["app_name"] == "SentinelDLP"


def test_readiness_endpoint_when_database_available(client: TestClient) -> None:
    """[Mocked Unit Test] Verify GET /health/ready returns 200 OK when DB is reachable."""
    with patch("app.services.health_service.check_db_connectivity") as mock_db:
        mock_db.return_value = (True, "Database operational", 1.25)
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "database" in data["components"]
        assert data["components"]["database"]["status"] == "up"
        assert data["components"]["database"]["message"] == "Database operational"
        assert data["components"]["database"]["latency_ms"] == 1.25


def test_readiness_endpoint_when_database_unavailable(client: TestClient) -> None:
    """[Mocked Unit Test] Verify GET /health/ready returns 503 SERVICE UNAVAILABLE when DB fails."""
    with patch("app.services.health_service.check_db_connectivity") as mock_db:
        mock_db.return_value = (False, "Database connection failure or timeout", 5000.0)
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unready"
        assert "database" in data["components"]
        assert data["components"]["database"]["status"] == "down"
        assert "Database connection failure" in data["components"]["database"]["message"]


def test_readiness_endpoint_v1_router_when_healthy(client: TestClient) -> None:
    """[Mocked Unit Test] Verify GET /api/v1/health/ready route functions identically."""
    with patch("app.services.health_service.check_db_connectivity") as mock_db:
        mock_db.return_value = (True, "Database operational", 0.85)
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
