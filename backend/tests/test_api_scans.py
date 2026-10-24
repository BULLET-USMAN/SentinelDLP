"""Integration Tests for Scanner API Endpoints (Phase 2).

Tests:
Start Scan -> Discover Files -> Extract Metadata -> Calculate Hashes -> Store Results -> Retrieve via API.
"""

import time
from fastapi.testclient import TestClient


def test_get_authorized_roots(client: TestClient) -> None:
    """Verify GET /api/v1/scanner/roots returns allowlisted roots."""
    response = client.get("/api/v1/scanner/roots")
    assert response.status_code == 200
    roots = response.json()
    assert isinstance(roots, list)
    assert len(roots) >= 1
    root_ids = [r["root_id"] for r in roots]
    assert "synthetic_samples" in root_ids


def test_create_scan_unauthorized_root(client: TestClient) -> None:
    """Verify POST /api/v1/scans rejects unauthorized arbitrary paths."""
    response = client.post(
        "/api/v1/scans",
        json={"root_id": "unauthorized_root_id_attempt"},
    )
    assert response.status_code == 403
    data = response.json()
    assert "not in the authorized administrator allowlist" in data.get("detail", "")


def test_full_scan_lifecycle_and_inventory(client: TestClient) -> None:
    """End-to-End Test: Start scan -> wait for completion -> inspect inventory and pagination."""
    # 1. Start scan on synthetic_samples
    create_resp = client.post(
        "/api/v1/scans",
        json={"root_id": "synthetic_samples"},
    )
    assert create_resp.status_code == 201
    job_data = create_resp.json()
    scan_id = job_data["id"]
    assert scan_id is not None
    assert job_data["root_id"] == "synthetic_samples"

    # 2. Poll status until completed (timeout after 10s)
    max_wait = 10.0
    start_time = time.time()
    final_status = job_data["status"]

    while (time.time() - start_time) < max_wait:
        status_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert status_resp.status_code == 200
        current_data = status_resp.json()
        final_status = current_data["status"]
        if final_status in ("completed", "failed", "cancelled"):
            job_data = current_data
            break
        time.sleep(0.2)

    assert final_status == "completed"
    assert job_data["files_processed"] > 0
    assert job_data["total_bytes_processed"] > 0

    # 3. Retrieve paginated files
    files_resp = client.get(f"/api/v1/scans/{scan_id}/files?page=1&size=5")
    assert files_resp.status_code == 200
    paginated = files_resp.json()
    assert paginated["total"] > 0
    assert len(paginated["items"]) <= 5
    assert paginated["page"] == 1
    assert paginated["pages"] >= 1

    # Check file item fields
    first_item = paginated["items"][0]
    assert "filename" in first_item
    assert "detected_type" in first_item
    assert "sha256_hash" in first_item
    assert "size_bytes" in first_item

    # 4. Test search filter
    search_resp = client.get(f"/api/v1/scans/{scan_id}/files?search=policy")
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert search_data["total"] >= 1
    assert any("policy" in item["filename"].lower() for item in search_data["items"])

    # 5. Test type mismatch filter (should catch disguised_text.pdf and spoofed_image.png)
    mismatch_resp = client.get(f"/api/v1/scans/{scan_id}/files?type_mismatch=true")
    assert mismatch_resp.status_code == 200
    mismatch_data = mismatch_resp.json()
    assert mismatch_data["total"] >= 1
    for item in mismatch_data["items"]:
        assert item["type_mismatch"] is True


def test_list_scans_history(client: TestClient) -> None:
    """Verify GET /api/v1/scans returns scan history list."""
    response = client.get("/api/v1/scans?limit=5")
    assert response.status_code == 200
    history = response.json()
    assert isinstance(history, list)
    assert len(history) >= 1


def test_cancel_non_existent_scan(client: TestClient) -> None:
    """Verify POST /api/v1/scans/{scan_id}/cancel returns 404 for invalid ID."""
    response = client.post("/api/v1/scans/non-existent-scan-id-1234/cancel")
    assert response.status_code == 404
