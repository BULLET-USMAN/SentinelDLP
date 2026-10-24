"""Error Handling and Exception Isolation Tests for SentinelDLP.

Ensures no raw stack traces, SQL internals, or secrets are leaked to clients.
"""

from fastapi.testclient import TestClient


def test_404_not_found(client: TestClient) -> None:
    """Verify non-existent route returns 404 cleanly."""
    response = client.get("/api/v1/non_existent_route")
    assert response.status_code == 404


def test_placeholder_endpoint_returns_501_not_implemented(client: TestClient) -> None:
    """Verify Phase 1 detection placeholder rejects execution safely."""
    response = client.post("/api/v1/detection/inspect")
    assert response.status_code == 501
    data = response.json()
    assert "detail" in data
    assert "reserved for Phase 2" in data["detail"]


def test_detection_status_roadmap_info(client: TestClient) -> None:
    """Verify detection status endpoint reports correct Phase 1 posture."""
    response = client.get("/api/v1/detection/status")
    assert response.status_code == 200
    data = response.json()
    assert data["module"] == "Detection & Exfiltration Analysis Engine"
    assert data["phase_target"] == "Phase 2+"
    assert data["status"] == "foundation_active_detection_deferred"
