"""Unit Tests for Suricata EVE JSON Log Adapter (Phase 7)."""

import json
from datetime import datetime, timezone
import pytest
from app.network.adapters.suricata_adapter import SuricataAdapter


def test_suricata_flow_parsing():
    """Verify parsing Suricata flow events with byte counters."""
    raw_flow = {
        "timestamp": "2026-10-25T16:00:00.000000+0000",
        "flow_id": 9988776655,
        "event_type": "flow",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "198.51.100.4",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "flow": {
            "bytes_toserver": 15000000,
            "bytes_toclient": 30000,
            "age": 28,
        },
    }
    event = SuricataAdapter.parse_eve_record(raw_flow)
    assert event is not None
    assert event.source_technology == "SURICATA"
    assert event.original_event_id == "9988776655"
    assert event.event_category == "FLOW"
    assert event.source_ip == "192.168.1.100"
    assert event.destination_ip == "198.51.100.4"
    assert event.bytes_source_to_dest == 15000000
    assert event.bytes_dest_to_source == 30000
    assert event.total_bytes == 15030000
    assert event.connection_duration_seconds == 28.0


def test_suricata_alert_parsing_and_severity_mapping():
    """Verify parsing Suricata alert events and mapping numerical severity."""
    # Suricata severity 1 -> CRITICAL
    raw_alert_crit = {
        "timestamp": "2026-10-25T16:01:00.000000+0000",
        "flow_id": 11223344,
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 54322,
        "dest_ip": "203.0.113.8",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "ET TROJAN High Volume Exfiltration Observed",
            "signature_id": 2028190,
            "severity": 1,
            "category": "A Network Trojan was detected",
        },
    }
    event_crit = SuricataAdapter.parse_eve_record(raw_alert_crit)
    assert event_crit is not None
    assert event_crit.event_category == "ALERT"
    assert event_crit.alert_signature == "ET TROJAN High Volume Exfiltration Observed"
    assert event_crit.alert_severity == "CRITICAL"

    # Suricata severity 2 -> HIGH
    raw_alert_high = dict(raw_alert_crit)
    raw_alert_high["alert"] = dict(raw_alert_crit["alert"], severity=2)
    assert SuricataAdapter.parse_eve_record(raw_alert_high).alert_severity == "HIGH"

    # Suricata severity 3 -> MEDIUM
    raw_alert_med = dict(raw_alert_crit)
    raw_alert_med["alert"] = dict(raw_alert_crit["alert"], severity=3)
    assert SuricataAdapter.parse_eve_record(raw_alert_med).alert_severity == "MEDIUM"


def test_suricata_dns_v1_and_v2_parsing():
    """Verify handling both DNS schema formats in Suricata."""
    # DNS Schema v1: dns.query object
    v1_record = {
        "timestamp": "2026-10-25T16:02:00.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.100",
        "src_port": 53000,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "query": {"rrname": "cloud-vault.corp", "rrtype": "A"},
            "rcode": "NOERROR",
        },
    }
    event_v1 = SuricataAdapter.parse_eve_record(v1_record)
    assert event_v1 is not None
    assert event_v1.event_category == "DNS"
    assert event_v1.dns_query == "cloud-vault.corp"

    # DNS Schema v2: dns.queries array
    v2_record = {
        "timestamp": "2026-10-25T16:02:05.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.100",
        "src_port": 53001,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "queries": [{"rrname": "api.github.com", "rrtype": "AAAA"}],
            "rcode": "NOERROR",
        },
    }
    event_v2 = SuricataAdapter.parse_eve_record(v2_record)
    assert event_v2 is not None
    assert event_v2.dns_query == "api.github.com"
    assert event_v2.dns_query_type == "AAAA"


def test_suricata_tls_and_http_parsing():
    """Verify parsing TLS SNI and HTTP hosts."""
    tls_record = {
        "timestamp": "2026-10-25T16:03:00.000000+0000",
        "event_type": "tls",
        "src_ip": "192.168.1.100",
        "dest_ip": "142.250.190.46",
        "dest_port": 443,
        "proto": "TCP",
        "tls": {"sni": "google.com", "version": "TLS 1.3"},
    }
    tls_event = SuricataAdapter.parse_eve_record(tls_record)
    assert tls_event is not None
    assert tls_event.tls_sni == "google.com"

    http_record = {
        "timestamp": "2026-10-25T16:04:00.000000+0000",
        "event_type": "http",
        "src_ip": "192.168.1.100",
        "dest_ip": "203.0.113.5",
        "dest_port": 80,
        "proto": "TCP",
        "http": {"hostname": "insecure-site.org", "http_method": "GET", "url": "/download/data?id=123"},
    }
    http_event = SuricataAdapter.parse_eve_record(http_record)
    assert http_event is not None
    assert http_event.http_host == "insecure-site.org"
    assert http_event.http_uri_stem == "/download/data"
