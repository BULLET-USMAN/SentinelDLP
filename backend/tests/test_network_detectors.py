"""Unit Tests for Network Detection Rules NET-001 through NET-010 (Phase 7)."""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from sqlalchemy.orm import Session
from app.models.monitoring import FileActivityEvent
from app.models.network import NetworkEvent, NetworkSensor, ThreatIntelIndicator
from app.network.detectors.connection_frequency import (
    MultiPortConnectionRule,
    RepeatedConnectionAttemptsRule,
)
from app.network.detectors.destination_analysis import UnfamiliarDestinationRule
from app.network.detectors.dns_anomalies import (
    DNSQueryPatternAnomaliesRule,
    UnusualDNSFrequencyRule,
)
from app.network.detectors.ids_alerts import SuricataSignatureAlertRule
from app.network.detectors.multi_signal import MultiSignalNetworkRule
from app.network.detectors.network_file_correlator import NetworkFileCorrelationRule
from app.network.detectors.traffic_volume import UnusualOutboundVolumeRule
from app.network.detectors.visibility_gap import NetworkVisibilityGapRule
from app.network.detectors.base import NetworkEvaluationContext


def make_mock_net_event(
    category: str = "CONNECTION",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "198.51.100.20",
    dst_port: int = 443,
    total_bytes: int = 1000,
    dns_query: str = None,
    tls_sni: str = None,
    alert_sig: str = None,
    alert_sev: str = None,
    delta_mins: int = 2,
) -> NetworkEvent:
    ev = MagicMock(spec=NetworkEvent)
    ev.id = f"ev-{hash((src_ip, dst_ip, total_bytes, delta_mins)) % 10000}"
    ev.sensor_id = "zeek-sensor-01"
    ev.source_technology = "ZEEK"
    ev.event_category = category
    ev.source_ip = src_ip
    ev.destination_ip = dst_ip
    ev.destination_port = dst_port
    ev.transport_protocol = "TCP"
    ev.application_protocol = "TLS" if dst_port == 443 else "HTTP" if dst_port == 80 else "DNS"
    ev.direction = "OUTBOUND"
    ev.total_bytes = total_bytes
    ev.bytes_source_to_dest = total_bytes
    ev.dns_query = dns_query
    ev.tls_sni = tls_sni
    ev.http_host = None
    ev.alert_signature = alert_sig
    ev.alert_severity = alert_sev
    ev.evidence_provenance = "IMPORTED"
    ev.timestamp = datetime.now(timezone.utc) - timedelta(minutes=delta_mins)
    return ev


class TestNetworkDetectors:
    """Test suite for NET-001 through NET-010."""

    def test_net_001_unusual_outbound_volume(self):
        rule = UnusualOutboundVolumeRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # Under threshold (5MB)
        ctx_under = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=[make_mock_net_event(total_bytes=5 * 1024 * 1024)],
        )
        assert rule.evaluate(ctx_under) is None

        # Over threshold (15MB)
        ctx_over = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=[make_mock_net_event(total_bytes=15 * 1024 * 1024)],
        )
        match = rule.evaluate(ctx_over)
        assert match is not None
        assert match.rule_id == "NET-001"
        assert match.score_contribution == 25
        assert match.severity_impact == "MEDIUM"

    def test_net_002_repeated_connection_attempts(self):
        rule = RepeatedConnectionAttemptsRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # 30 rapid connections from same source
        conns = [
            make_mock_net_event(src_ip="192.168.1.100", dst_ip=f"10.0.0.{i}", delta_mins=i % 5)
            for i in range(30)
        ]
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=conns,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-002"
        assert match.score_contribution == 20

    def test_net_003_multi_port_connection_activity(self):
        rule = MultiPortConnectionRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # Source contacts 20 distinct ports
        conns = [
            make_mock_net_event(src_ip="192.168.1.100", dst_port=1000 + i)
            for i in range(20)
        ]
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=conns,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-003"
        assert match.evidence["distinct_ports_count"] == 20

    def test_net_004_unusual_dns_frequency(self):
        rule = UnusualDNSFrequencyRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # 35 queries from same source
        dns_events = [
            make_mock_net_event(category="DNS", src_ip="192.168.1.100", dns_query=f"query{i}.corp")
            for i in range(35)
        ]
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            dns_events=dns_events,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-004"
        assert match.evidence["dns_query_count"] == 35

    def test_net_005_dns_query_pattern_anomalies(self):
        rule = DNSQueryPatternAnomaliesRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # Anomalous high-entropy long query name
        long_query = "v94a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a.exfil-tunnel.biz"
        dns_events = [make_mock_net_event(category="DNS", dns_query=long_query)]

        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            dns_events=dns_events,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-005"
        assert match.score_contribution == 35
        assert "tunneling" in match.explanation

    def test_net_006_unfamiliar_destination(self):
        rule = UnfamiliarDestinationRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)
        db.query.return_value.filter.return_value.all.return_value = []

        # Connection to unapproved external destination (mega.nz)
        conns = [make_mock_net_event(dst_ip="31.216.145.8", tls_sni="mega.nz")]
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=conns,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-006"
        assert match.severity_impact == "MEDIUM"

    def test_net_007_suricata_signature_alert(self):
        rule = SuricataSignatureAlertRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        alert_evt = make_mock_net_event(
            category="ALERT",
            alert_sig="ET MALWARE Data Exfiltration Attempt",
            alert_sev="CRITICAL",
        )
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            ids_alerts=[alert_evt],
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-007"
        assert match.severity_impact == "CRITICAL"
        assert match.score_contribution == 40

    def test_net_008_network_file_correlation(self):
        rule = NetworkFileCorrelationRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # Mock sensitive file in DB
        sens_file = MagicMock(spec=FileActivityEvent)
        sens_file.file_path = "confidential_customer_data.xlsx"
        sens_file.sensitivity_label = "RESTRICTED"
        sens_file.occurred_at = now - timedelta(minutes=8)
        db.query.return_value.filter.return_value.all.return_value = [sens_file]

        # Correlating outbound connection
        conns = [make_mock_net_event(total_bytes=10_000_000, dst_ip="31.216.145.8", tls_sni="mega.nz")]
        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=conns,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-008"
        assert match.score_contribution == 45
        assert match.relationship_type == "circumstantial"
        assert match.evidence["payload_contents_verified"] is False

    def test_net_009_network_visibility_gap(self):
        rule = NetworkVisibilityGapRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)

        # Mock sensor with visibility gap
        degraded_sensor = MagicMock(spec=NetworkSensor)
        degraded_sensor.sensor_id = "zeek-sensor-01"
        degraded_sensor.technology = "ZEEK"
        degraded_sensor.health_status = "VISIBILITY_GAP"
        degraded_sensor.coverage_gap_reason = "Log buffer dropped 1200 packets"
        db.query.return_value.filter.return_value.all.return_value = [degraded_sensor]

        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-009"
        assert match.score_contribution == 10
        assert match.severity_impact == "LOW"

    def test_net_010_multi_signal_network_investigation(self):
        rule = MultiSignalNetworkRule()
        now = datetime.now(timezone.utc)
        db = MagicMock(spec=Session)
        db.query.return_value.filter.return_value.all.return_value = []

        conns = [make_mock_net_event(total_bytes=8 * 1024 * 1024, tls_sni="mega.nz")]
        dns_events = [make_mock_net_event(category="DNS", dns_query="v94a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a.tunnel.biz")]
        ids_alerts = [make_mock_net_event(category="ALERT", alert_sig="ET C2 Beacon Detected")]

        ctx = NetworkEvaluationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            db=db,
            connections=conns,
            dns_events=dns_events,
            ids_alerts=ids_alerts,
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "NET-010"
        assert match.severity_impact == "CRITICAL"
        assert match.score_contribution == 50
