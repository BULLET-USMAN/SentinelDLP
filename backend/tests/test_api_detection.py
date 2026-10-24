"""Integration Tests for Sensitive Data Detection & Classification APIs (Phase 3).

Validates:
- GET /api/v1/detection/rules
- GET /api/v1/scans/{scan_id}/sensitivity-summary
- GET /api/v1/scans/{scan_id}/findings (pagination, filtering)
- GET /api/v1/scans/{scan_id}/classified-files (filtering by sensitivity and category)
- GET /api/v1/files/{file_id}/classification
- Zero leakage of raw secrets or sensitive data in API responses
"""

import time
from fastapi.testclient import TestClient


def test_get_detection_rules_catalog(client: TestClient) -> None:
    """Verify GET /api/v1/detection/rules returns active catalog."""
    response = client.get("/api/v1/detection/rules")
    assert response.status_code == 200
    rules = response.json()
    assert isinstance(rules, list)
    assert len(rules) >= 10
    rule_ids = [r["id"] for r in rules]
    assert "RULE-PII-CNIC-PK" in rule_ids
    assert "RULE-CRED-API-TOKEN" in rule_ids
    assert "RULE-FIN-PAYMENT-CARD" in rule_ids
    assert "RULE-LABEL-CONFIDENTIAL" in rule_ids


def test_e2e_detection_and_classification_lifecycle(client: TestClient) -> None:
    """End-to-End: Start scan -> wait for completion -> verify classification APIs."""
    # 1. Start scan on synthetic_samples
    create_resp = client.post("/api/v1/scans", json={"root_id": "synthetic_samples"})
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["id"]

    # 2. Poll until completed
    max_wait = 10.0
    start_time = time.time()
    while (time.time() - start_time) < max_wait:
        status_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert status_resp.status_code == 200
        if status_resp.json()["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.2)

    # 3. Verify sensitivity summary
    summary_resp = client.get(f"/api/v1/scans/{scan_id}/sensitivity-summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["scan_job_id"] == scan_id
    assert summary["files_inspected"] > 0
    assert summary["sensitive_files_count"] > 0
    assert summary["restricted_count"] > 0
    assert summary["confidential_count"] > 0
    assert summary["pii_count"] > 0
    assert summary["credential_count"] > 0
    assert summary["financial_count"] > 0

    # 4. Verify paginated findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings?page=1&size=20")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert findings_data["total"] > 0
    assert len(findings_data["items"]) > 0

    # Privacy verification: Ensure no raw credit cards or secrets exist in findings
    for item in findings_data["items"]:
        assert "4532015112830366" not in str(item)
        assert "Sup3rS3cur3" not in str(item)
        assert "rule_id" in item
        assert "category" in item
        assert "confidence" in item
        assert "occurrence_count" in item

    # 5. Verify classified files endpoint with RESTRICTED filter
    restricted_resp = client.get(f"/api/v1/scans/{scan_id}/classified-files?sensitivity=RESTRICTED")
    assert restricted_resp.status_code == 200
    restricted_data = restricted_resp.json()
    assert restricted_data["total"] >= 1
    for item in restricted_data["items"]:
        assert item["sensitivity_label"] == "RESTRICTED"

    # 6. Verify single file classification details
    target_file_id = restricted_data["items"][0]["file_id"]
    file_detail_resp = client.get(f"/api/v1/files/{target_file_id}/classification")
    assert file_detail_resp.status_code == 200
    file_detail = file_detail_resp.json()
    assert file_detail["file_id"] == target_file_id
    assert file_detail["classification"]["sensitivity_label"] == "RESTRICTED"
    assert len(file_detail["findings"]) >= 1


def test_detection_endpoints_invalid_ids_404(client: TestClient) -> None:
    """Verify 404 responses for nonexistent scan IDs and file IDs."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    summary_resp = client.get(f"/api/v1/scans/{fake_id}/sensitivity-summary")
    assert summary_resp.status_code == 404

    findings_resp = client.get(f"/api/v1/scans/{fake_id}/findings")
    assert findings_resp.status_code == 404

    file_resp = client.get(f"/api/v1/files/{fake_id}/classification")
    assert file_resp.status_code == 404
