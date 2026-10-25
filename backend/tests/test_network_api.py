"""Integration Tests for Network Monitoring & Threat Intelligence API (Phase 7)."""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient


def test_api_network_status_and_sensors(client: TestClient):
    """Verify status and sensors endpoints."""
    resp = client.get("/api/v1/network/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "sensors_total" in data

    sensors_resp = client.get("/api/v1/network/sensors")
    assert sensors_resp.status_code == 200
    assert isinstance(sensors_resp.json(), list)


def test_api_network_rules(client: TestClient):
    """Verify all 10 network detection rules are exposed via the catalog API."""
    resp = client.get("/api/v1/network/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 10
    rule_ids = [r["rule_id"] for r in data]
    for i in range(1, 11):
        num_str = f"NET-0{i:02d}" if i >= 10 else f"NET-00{i}"
        assert num_str in rule_ids


def test_api_network_simulate_and_analytics(client: TestClient):
    """Verify simulating synthetic network telemetry and querying statistics."""
    # Simulate mixed scenario
    sim_resp = client.post("/api/v1/network/simulate", json={"scenario_type": "mixed_traffic"})
    assert sim_resp.status_code == 201
    sim_data = sim_resp.json()
    assert sim_data["records_processed"] >= 4
    assert sim_data["status"] == "COMPLETED"

    # Verify statistics reflect records
    stats_resp = client.get("/api/v1/network/statistics")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_connections"] >= 1
    assert stats["active_sensors_count"] >= 1

    # Verify connections list
    conns_resp = client.get("/api/v1/network/connections?limit=10")
    assert conns_resp.status_code == 200
    conns_data = conns_resp.json()
    assert conns_data["total"] >= 1
    assert len(conns_data["items"]) >= 1

    # Verify destinations
    dest_resp = client.get("/api/v1/network/destinations")
    assert dest_resp.status_code == 200
    dest_data = dest_resp.json()
    assert isinstance(dest_data, list)
    assert len(dest_data) >= 1

    # Verify DNS intelligence
    dns_resp = client.get("/api/v1/network/dns")
    assert dns_resp.status_code == 200
    dns_data = dns_resp.json()
    assert "total_queries" in dns_data
    assert dns_data["total_queries"] >= 1

    # Verify Traffic summary
    traffic_resp = client.get("/api/v1/network/traffic-summary?interval=24h")
    assert traffic_resp.status_code == 200
    traffic_data = traffic_resp.json()
    assert traffic_data["interval"] == "24h"
    assert len(traffic_data["points"]) == 12


def test_api_network_ingest_direct_content_and_deduplication(client: TestClient):
    """Verify ingesting raw Zeek JSON lines and testing duplicate rejection."""
    run_id = uuid.uuid4().hex[:6]
    uid1 = f"API-ZEEK-{run_id}-001"
    uid2 = f"API-ZEEK-{run_id}-002"
    raw_zeek_lines = f"""{{"ts": 1729864900.0, "uid": "{uid1}", "id.orig_h": "192.168.1.80", "id.orig_p": 45000, "id.resp_h": "93.184.216.34", "id.resp_p": 80, "proto": "tcp", "orig_bytes": 1200, "resp_bytes": 4800}}
{{"ts": 1729864905.0, "uid": "{uid2}", "id.orig_h": "192.168.1.80", "id.orig_p": 45001, "id.resp_h": "93.184.216.34", "id.resp_p": 80, "proto": "tcp", "orig_bytes": 1500, "resp_bytes": 3200}}
"""
    payload = {
        "sensor_id": f"zeek-api-{run_id}",
        "source_format": "ZEEK_CONN",
        "raw_content": raw_zeek_lines,
    }

    # Initial import: 2 records processed, 0 duplicates
    resp1 = client.post("/api/v1/network/ingest", json=payload)
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["records_processed"] == 2
    assert data1["duplicate_count"] == 0

    # Repeated import: 0 processed, 2 duplicates
    resp2 = client.post("/api/v1/network/ingest", json=payload)
    assert resp2.status_code == 201
    data2 = resp2.json()
    assert data2["records_processed"] == 0
    assert data2["duplicate_count"] == 2


def test_api_threat_intel_indicators(client: TestClient):
    """Verify creating and listing threat intelligence indicators."""
    payload = {
        "indicator_type": "DOMAIN",
        "indicator_value": "c2-exfil-sinkhole.net",
        "category": "MALICIOUS",
        "source_feed": "LOCAL_SOC_REPORT",
        "confidence": "HIGH",
        "description": "Observed in test scenario",
    }
    create_resp = client.post("/api/v1/network/threat-intel/indicators", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["indicator_value"] == "c2-exfil-sinkhole.net"
    assert created["category"] == "MALICIOUS"

    list_resp = client.get("/api/v1/network/threat-intel/indicators")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(i["indicator_value"] == "c2-exfil-sinkhole.net" for i in items)
