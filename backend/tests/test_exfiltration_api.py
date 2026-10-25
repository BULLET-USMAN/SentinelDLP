"""Integration Tests for Exfiltration API Endpoints (Phase 6)."""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient


def test_api_list_rules(client: TestClient):
    """Verify all 8 exfiltration detection rules are exposed via the catalog API."""
    response = client.get("/api/v1/exfiltration/rules")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 8
    rule_ids = [r["rule_id"] for r in data]
    for i in range(1, 9):
        assert f"EXFIL-00{i}" in rule_ids


def test_api_get_statistics(client: TestClient):
    """Verify statistics endpoint returns valid metrics."""
    response = client.get("/api/v1/exfiltration/statistics")
    assert response.status_code == 200
    data = response.json()
    assert "total_investigations" in data
    assert "rules_active_count" in data
    assert data["rules_active_count"] == 8


def test_api_transfers_simulate_and_list(client: TestClient):
    """Verify lab synthetic transfer simulation and listing."""
    # Simulate cloud exfiltration scenario
    sim_resp = client.post("/api/v1/exfiltration/transfers/simulate?scenario_type=cloud_exfiltration")
    assert sim_resp.status_code == 201
    sim_data = sim_resp.json()
    assert len(sim_data) >= 1
    assert sim_data[0]["evidence_provenance"] == "LAB_SIMULATED"
    assert sim_data[0]["is_simulated"] is True
    assert "mega.nz" in sim_data[0]["destination_host"]

    # List transfers
    list_resp = client.get("/api/v1/exfiltration/transfers?limit=10")
    assert list_resp.status_code == 200
    transfers = list_resp.json()
    assert len(transfers) >= 1


def test_api_batch_import_transfers(client: TestClient):
    """Verify batch import of external or synthetic transfer events."""
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "events": [
            {
                "source_endpoint_id": "endpoint-test-01",
                "occurred_at": now_iso,
                "direction": "OUTBOUND",
                "destination_category": "EXTERNAL_IP",
                "destination_host": "203.0.113.5",
                "protocol": "SFTP",
                "byte_count": 8_500_000,
                "evidence_source": "TEST_HARNESS",
                "evidence_provenance": "LAB_SIMULATED",
                "is_simulated": True,
            }
        ]
    }
    resp = client.post("/api/v1/exfiltration/transfers/import", json=payload)
    assert resp.status_code == 201
    imported = resp.json()
    assert len(imported) == 1
    assert imported[0]["destination_host"] == "203.0.113.5"


def test_api_correlation_and_investigation_lifecycle(client: TestClient):
    """Verify running correlation pass, retrieving investigations, timeline, and updating status."""
    # Run correlation pass
    corr_resp = client.post("/api/v1/exfiltration/correlate", json={"window_minutes": 60})
    assert corr_resp.status_code == 200
    corr_data = corr_resp.json()
    assert "investigations_created" in corr_data
    assert corr_data["rules_evaluated"] == 8

    # Query investigations
    inv_resp = client.get("/api/v1/exfiltration/investigations")
    assert inv_resp.status_code == 200
    inv_list = inv_resp.json()
    assert isinstance(inv_list, list)

    if inv_list:
        target_inv = inv_list[0]
        inv_id = target_inv["id"]

        # Get details
        detail_resp = client.get(f"/api/v1/exfiltration/investigations/{inv_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["id"] == inv_id

        # Get timeline
        timeline_resp = client.get(f"/api/v1/exfiltration/investigations/{inv_id}/timeline")
        assert timeline_resp.status_code == 200
        timeline = timeline_resp.json()
        assert isinstance(timeline, list)

        # Update status: transition to INVESTIGATING
        patch_resp = client.patch(
            f"/api/v1/exfiltration/investigations/{inv_id}/status",
            json={
                "status": "INVESTIGATING",
                "assigned_analyst": "sec-analyst-lead",
                "notes": "Analyst investigating correlated archive transfer.",
            },
        )
        assert patch_resp.status_code == 200
        updated = patch_resp.json()
        assert updated["status"] == "INVESTIGATING"
        assert updated["assigned_analyst"] == "sec-analyst-lead"
        assert "investigating correlated archive transfer" in updated["investigation_notes"]
