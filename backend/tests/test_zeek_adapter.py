"""Unit Tests for Zeek Log Ingestion Adapter (Phase 7)."""

import json
from datetime import datetime, timezone
import pytest
from app.network.adapters.zeek_adapter import ZeekAdapter


def test_zeek_conn_log_parsing():
    """Verify parsing standard Zeek conn.log JSON lines."""
    raw_conn = {
        "ts": 1729864800.123,
        "uid": "CZk1234567890",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 49152,
        "id.resp_h": "31.216.145.8",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 5.25,
        "orig_bytes": 10500000,
        "resp_bytes": 12000,
        "conn_state": "SF",
    }
    event = ZeekAdapter.parse_conn_record(raw_conn)
    assert event is not None
    assert event.sensor_id == "zeek-sensor-01"
    assert event.source_technology == "ZEEK"
    assert event.original_event_id == "CZk1234567890"
    assert event.event_category == "CONNECTION"
    assert event.source_ip == "192.168.1.50"
    assert event.source_port == 49152
    assert event.destination_ip == "31.216.145.8"
    assert event.destination_port == 443
    assert event.transport_protocol == "TCP"
    assert event.application_protocol == "SSL"
    assert event.bytes_source_to_dest == 10500000
    assert event.total_bytes == 10512000
    assert event.connection_duration_seconds == 5.25


def test_zeek_dns_log_parsing():
    """Verify parsing Zeek dns.log JSON lines."""
    raw_dns = {
        "ts": 1729864810.0,
        "uid": "CDns987654321",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 53211,
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "storage.googleapis.com",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": ["142.250.190.46"],
    }
    event = ZeekAdapter.parse_dns_record(raw_dns)
    assert event is not None
    assert event.event_category == "DNS"
    assert event.dns_query == "storage.googleapis.com"
    assert event.dns_query_type == "A"
    assert event.dns_response_code == "NOERROR"


def test_zeek_ssl_log_parsing():
    """Verify parsing Zeek ssl.log / tls.log JSON lines."""
    raw_ssl = {
        "ts": 1729864820.0,
        "uid": "CSsl11223344",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 49152,
        "id.resp_h": "31.216.145.8",
        "id.resp_p": 443,
        "server_name": "mega.nz",
        "version": "TLSv13",
        "cipher": "TLS_AES_256_GCM_SHA384",
    }
    event = ZeekAdapter.parse_ssl_record(raw_ssl)
    assert event is not None
    assert event.event_category == "TLS"
    assert event.tls_sni == "mega.nz"
    assert event.tls_version == "TLSv13"


def test_zeek_http_log_privacy_sanitization():
    """Verify URI query parameters are stripped and no bodies captured."""
    raw_http = {
        "ts": 1729864830.0,
        "uid": "CHttp556677",
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 49153,
        "id.resp_h": "203.0.113.10",
        "id.resp_p": 80,
        "method": "POST",
        "host": "api.external.com",
        "uri": "/upload/v1?token=SECRET12345&user=admin",
        "response_body_len": 450,
    }
    event = ZeekAdapter.parse_http_record(raw_http)
    assert event is not None
    assert event.http_method == "POST"
    assert event.http_host == "api.external.com"
    assert event.http_uri_stem == "/upload/v1"
    assert "SECRET" not in (event.http_uri_stem or "")


def test_zeek_stream_parser_error_handling():
    """Verify streaming line parser handles malformed lines and comments."""
    log_data = """#separator \\x09
#set_separator	,
{"ts": 1729864800.0, "uid": "C1", "id.orig_h": "10.0.0.1", "id.orig_p": 1234, "id.resp_h": "10.0.0.2", "id.resp_p": 80, "proto": "tcp"}
INVALID JSON LINE HERE
{"ts": 1729864801.0, "uid": "C2", "proto": "tcp"}
{"ts": 1729864802.0, "uid": "C3", "id.orig_h": "10.0.0.1", "id.orig_p": 1235, "id.resp_h": "10.0.0.2", "id.resp_p": 80, "proto": "tcp"}
"""
    results = list(ZeekAdapter.stream_parse_lines(iter(log_data.splitlines()), format_type="ZEEK_CONN"))
    # Expected: 2 valid records (C1 and C3), 1 malformed JSON error, 1 missing endpoint error
    valid_events = [res[0] for res in results if res[1]]
    assert len(valid_events) == 2
    assert valid_events[0].original_event_id == "C1"
    assert valid_events[1].original_event_id == "C3"
