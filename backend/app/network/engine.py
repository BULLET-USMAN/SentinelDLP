"""Network Monitoring and Detection Engine Facade for SentinelDLP (Phase 7).

Coordinates log parsing, threat intelligence lookups, rule evaluation,
and correlation bridges.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from app.network.detectors import get_all_network_rules
from app.network.schemas import (
    NetworkIngestResponse,
    NetworkRuleDefinitionResponse,
    NormalizedNetworkEvent,
)
from app.network.services.correlation_service import NetworkCorrelationService
from app.network.services.ingestion_service import NetworkIngestionService


class NetworkEngine:
    """Facade for network monitoring, detection rules, and telemetry processing."""

    @staticmethod
    def get_registered_rules() -> List[NetworkRuleDefinitionResponse]:
        """Return specifications of all 10 network detection rules."""
        definitions = []
        for rule in get_all_network_rules():
            definitions.append(
                NetworkRuleDefinitionResponse(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    version=rule.version,
                    description=rule.description,
                    severity_impact=rule.severity_impact,
                    required_events=rule.required_events,
                    relationship_type=rule.relationship_type,
                )
            )
        return definitions

    @staticmethod
    def execute_detection_pass(db: Session, window_minutes: int = 15):
        """Execute all network detection rules across recent telemetry."""
        return NetworkCorrelationService.evaluate_network_rules(db=db, window_minutes=window_minutes)

    @staticmethod
    def ingest_telemetry(
        db: Session,
        sensor_id: str,
        source_format: str,
        file_path: Optional[str] = None,
        raw_content: Optional[str] = None,
    ) -> NetworkIngestResponse:
        """Process and store network logs or PCAP traces."""
        return NetworkIngestionService.ingest_stream_or_file(
            db=db,
            sensor_id=sensor_id,
            source_format=source_format,
            file_path=file_path,
            raw_content=raw_content,
        )

    @classmethod
    def simulate_scenario(cls, db: Session, scenario_type: str = "mixed_traffic") -> NetworkIngestResponse:
        """Generate realistic synthetic Zeek/Suricata telemetry for demonstration and verification."""
        now = datetime.now(timezone.utc)
        events_to_add: List[NormalizedNetworkEvent] = []

        if scenario_type in ("normal_traffic", "mixed_traffic"):
            # Normal DNS & HTTPS to Google & Microsoft
            events_to_add.append(
                NormalizedNetworkEvent(
                    sensor_id="zeek-sensor-01",
                    source_technology="ZEEK",
                    original_event_id=f"sim-norm-{int(now.timestamp())}-1",
                    event_category="DNS",
                    timestamp=now - timedelta(minutes=5),
                    source_ip="192.168.1.105",
                    source_port=52341,
                    destination_ip="1.1.1.1",
                    destination_port=53,
                    transport_protocol="UDP",
                    application_protocol="DNS",
                    dns_query="storage.googleapis.com",
                    dns_query_type="A",
                    dns_response_code="NOERROR",
                    is_simulated=True,
                    evidence_provenance="LAB_SIMULATED",
                )
            )
            events_to_add.append(
                NormalizedNetworkEvent(
                    sensor_id="zeek-sensor-01",
                    source_technology="ZEEK",
                    original_event_id=f"sim-norm-{int(now.timestamp())}-2",
                    event_category="CONNECTION",
                    timestamp=now - timedelta(minutes=4),
                    source_ip="192.168.1.105",
                    source_port=52342,
                    destination_ip="142.250.190.46",
                    destination_port=443,
                    transport_protocol="TCP",
                    application_protocol="TLS",
                    tls_sni="storage.googleapis.com",
                    connection_duration_seconds=12.4,
                    bytes_source_to_dest=45000,
                    bytes_dest_to_source=120000,
                    total_bytes=165000,
                    is_simulated=True,
                    evidence_provenance="LAB_SIMULATED",
                )
            )

        if scenario_type in ("high_outbound", "mixed_traffic"):
            # Large volume outbound transfer (>15MB) to mega.nz
            events_to_add.append(
                NormalizedNetworkEvent(
                    sensor_id="zeek-sensor-01",
                    source_technology="ZEEK",
                    original_event_id=f"sim-high-{int(now.timestamp())}-3",
                    event_category="CONNECTION",
                    timestamp=now - timedelta(minutes=2),
                    source_ip="192.168.1.105",
                    source_port=49152,
                    destination_ip="31.216.145.8",
                    destination_port=443,
                    transport_protocol="TCP",
                    application_protocol="TLS",
                    tls_sni="mega.nz",
                    connection_duration_seconds=45.2,
                    bytes_source_to_dest=18_500_000,  # 18.5 MB
                    bytes_dest_to_source=25_000,
                    total_bytes=18_525_000,
                    is_simulated=True,
                    evidence_provenance="LAB_SIMULATED",
                )
            )

        if scenario_type in ("dns_tunnel_anomaly", "mixed_traffic"):
            # Anomalous high-entropy DNS query
            events_to_add.append(
                NormalizedNetworkEvent(
                    sensor_id="zeek-sensor-01",
                    source_technology="ZEEK",
                    original_event_id=f"sim-dns-{int(now.timestamp())}-4",
                    event_category="DNS",
                    timestamp=now - timedelta(minutes=3),
                    source_ip="192.168.1.105",
                    source_port=58912,
                    destination_ip="8.8.8.8",
                    destination_port=53,
                    transport_protocol="UDP",
                    application_protocol="DNS",
                    dns_query="v19a48fbc923a48e718bc9910a24ef9834ba77.exfil-c2-tunnel.biz",
                    dns_query_type="TXT",
                    dns_response_code="NOERROR",
                    is_simulated=True,
                    evidence_provenance="LAB_SIMULATED",
                )
            )

        if scenario_type in ("suricata_alert", "mixed_traffic"):
            # Suricata Alert for outbound anomalous transfer
            events_to_add.append(
                NormalizedNetworkEvent(
                    sensor_id="suricata-sensor-01",
                    source_technology="SURICATA",
                    original_event_id=f"sim-alert-{int(now.timestamp())}-5",
                    event_category="ALERT",
                    timestamp=now - timedelta(minutes=2),
                    source_ip="192.168.1.105",
                    source_port=49152,
                    destination_ip="31.216.145.8",
                    destination_port=443,
                    transport_protocol="TCP",
                    application_protocol="TLS",
                    alert_signature="ET EXPLOIT Suspicious Outbound Cloud Storage POST",
                    alert_severity="HIGH",
                    total_bytes=18_525_000,
                    is_simulated=True,
                    evidence_provenance="LAB_SIMULATED",
                )
            )

        # Ingest directly
        sensor = NetworkIngestionService.ensure_sensor(db, sensor_id="zeek-sensor-01", technology="ZEEK")
        suricata_sensor = NetworkIngestionService.ensure_sensor(db, sensor_id="suricata-sensor-01", technology="SURICATA")

        db_models = [NetworkIngestionService._to_db_model(ev) for ev in events_to_add]
        db.bulk_save_objects(db_models)
        db.commit()

        # Run correlation pass
        cls.execute_detection_pass(db, window_minutes=15)

        return NetworkIngestResponse(
            job_id="sim-job-001",
            sensor_id="multi-sensor-sim",
            source_format="SIMULATED",
            records_processed=len(events_to_add),
            records_rejected=0,
            duplicate_count=0,
            status="COMPLETED",
            timestamp=datetime.now(timezone.utc),
        )


# Global Engine Instance
network_engine = NetworkEngine()
