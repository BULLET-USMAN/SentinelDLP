"""Integration Tests for Real-Time File Activity Monitoring (Phase 4).

Validates:
- GET /api/v1/monitoring/roots
- POST /api/v1/monitoring/start and POST /api/v1/monitoring/stop
- Unauthorized root rejection (403)
- Live filesystem event workflow:
  File Create -> Watcher -> Deduplicator -> Queue -> Database -> Classification Update -> API.
- Modification and Deletion telemetry
- GET /api/v1/monitoring/statistics
"""

from pathlib import Path
import time
from fastapi.testclient import TestClient
from app.core.config import settings
from app.monitoring.manager import monitoring_manager


def test_get_monitoring_roots(client: TestClient) -> None:
    """Verify GET /api/v1/monitoring/roots returns allowlisted roots."""
    resp = client.get("/api/v1/monitoring/roots")
    assert resp.status_code == 200
    roots = resp.json()
    assert isinstance(roots, list)
    assert len(roots) >= 1
    root_ids = [r["root_id"] for r in roots]
    assert "synthetic_samples" in root_ids


def test_unauthorized_root_start_rejected(client: TestClient) -> None:
    """Verify POST /api/v1/monitoring/start rejects unauthorized root IDs."""
    resp = client.post(
        "/api/v1/monitoring/start",
        json={"root_id": "unauthorized_malicious_root"},
    )
    assert resp.status_code == 403
    assert "Security Boundary Violation" in resp.json()["detail"]


def test_monitoring_start_stop_lifecycle(client: TestClient) -> None:
    """Verify starting and stopping a watcher."""
    # 1. Start monitoring on synthetic_samples
    start_resp = client.post(
        "/api/v1/monitoring/start",
        json={"root_id": "synthetic_samples", "recursive": True},
    )
    assert start_resp.status_code == 200
    start_data = start_resp.json()
    assert start_data["root_id"] == "synthetic_samples"
    assert start_data["status"] in ("active", "starting")
    assert start_data["session_id"] is not None

    # 2. Check status endpoint
    status_resp = client.get("/api/v1/monitoring/status?root_id=synthetic_samples")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "active"

    # 3. Stop monitoring
    stop_resp = client.post(
        "/api/v1/monitoring/stop",
        json={"root_id": "synthetic_samples"},
    )
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "stopped"


def test_live_filesystem_activity_and_classification(client: TestClient) -> None:
    """Full Pipeline Test:

    Start monitoring -> Create sensitive file -> Verify event & classification ->
    Modify file to restricted -> Verify reclassification -> Delete file -> Verify deletion event.
    """
    root_meta = settings.get_authorized_roots().get("synthetic_samples", {})
    samples_dir = Path(root_meta.get("path", "./sample_data")).resolve()
    samples_dir.mkdir(parents=True, exist_ok=True)

    test_file = samples_dir / "live_activity_test.txt"
    test_file.unlink(missing_ok=True)

    # 1. Start monitoring
    start_resp = client.post(
        "/api/v1/monitoring/start",
        json={"root_id": "synthetic_samples", "recursive": True},
    )
    assert start_resp.status_code == 200

    try:
        # Give observer thread time to initialize
        time.sleep(0.5)

        # 2. Action: Create file with PII (triggers CONFIDENTIAL)
        test_file.write_text(
            "Customer Record: Muhammad Bilal\n"
            "CNIC: 35201-7654321-9\n"
            "Email: bilal.test@corp-internal.pk\n",
            encoding="utf-8",
        )

        # Allow time for watchdog -> queue -> event_processor
        time.sleep(1.2)

        # Query events via API
        events_resp = client.get("/api/v1/monitoring/events?root_id=synthetic_samples&search=live_activity_test")
        assert events_resp.status_code == 200
        events_data = events_resp.json()
        assert events_data["total"] >= 1

        first_event = events_data["items"][0]
        assert "live_activity_test.txt" in first_event["relative_path"]
        assert first_event["status"] == "processed"
        assert first_event["sensitivity_label"] in ("CONFIDENTIAL", "RESTRICTED")

        # 3. Action: Modify file by appending high-impact private key (triggers RESTRICTED)
        test_file.write_text(
            "Customer Record: Muhammad Bilal\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0mYFakeKeySyntheticOnlyDoNotUse1234567890ABCDEF\n"
            "-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        time.sleep(1.2)

        # Query updated events
        mod_resp = client.get("/api/v1/monitoring/events?root_id=synthetic_samples&search=live_activity_test")
        assert mod_resp.status_code == 200
        mod_items = mod_resp.json()["items"]
        assert len(mod_items) >= 2

        # Check latest event has escalated to RESTRICTED
        latest_event = mod_items[0]
        assert latest_event["sensitivity_label"] == "RESTRICTED"

        # 4. Action: Delete file
        test_file.unlink(missing_ok=True)
        time.sleep(1.2)

        del_resp = client.get("/api/v1/monitoring/events?root_id=synthetic_samples&event_type=FILE_DELETED")
        assert del_resp.status_code == 200
        del_items = del_resp.json()["items"]
        assert any("live_activity_test.txt" in item["relative_path"] for item in del_items)

        # 5. Check statistics endpoint
        stats_resp = client.get("/api/v1/monitoring/statistics?root_id=synthetic_samples")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_events"] >= 3
        assert stats["created_count"] >= 1
        assert stats["deleted_count"] >= 1

    finally:
        # Clean up watcher and temporary file
        client.post("/api/v1/monitoring/stop", json={"root_id": "synthetic_samples"})
        test_file.unlink(missing_ok=True)
