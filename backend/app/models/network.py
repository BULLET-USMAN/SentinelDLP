"""Network Telemetry, Sensor, and IDS Event Database Models for SentinelDLP (Phase 7).

Defines persistence schemas for:
- NetworkSensor: Registered network monitors (Zeek, Suricata, PCAP Analyzers).
- NetworkEvent: Unified normalized network event telemetry (connections, DNS, HTTP, TLS, IDS alerts).
- NetworkAlertReference: Correlated IDS alerts linked to SentinelDLP alert system.
- NetworkIngestionJob: Batch log/PCAP ingestion jobs with audit counters.
- NetworkBaseline: Configurable baseline thresholds for outbound volume and frequency.
- ThreatIntelIndicator: Local destination-context indicators (IPs, domains, CIDRs).

Strict Privacy & Security Principles:
- Zero raw packet payload or unmasked credential storage.
- Explicit evidence provenance: OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED.
- Full UTC normalization for all temporal analysis.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.db.base import Base


class NetworkSensor(Base):
    """Represents a network monitoring sensor or telemetry source (e.g. Zeek, Suricata)."""

    __tablename__ = "network_sensors"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sensor_id = Column(String(64), unique=True, nullable=False, index=True)
    technology = Column(String(32), nullable=False, index=True)  # ZEEK, SURICATA, PCAP_ANALYZER
    version = Column(String(32), nullable=True)
    configuration_reference = Column(String(255), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    last_import_at = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(
        String(32), nullable=False, default="ACTIVE", index=True
    )  # ACTIVE, DEGRADED, OFFLINE, VISIBILITY_GAP
    coverage_gap_reason = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    events = relationship("NetworkEvent", back_populates="sensor", cascade="all, delete-orphan")
    ingestion_jobs = relationship("NetworkIngestionJob", back_populates="sensor", cascade="all, delete-orphan")


class NetworkEvent(Base):
    """Unified normalized network event representing connections, DNS queries, TLS/HTTP sessions, or flows."""

    __tablename__ = "network_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sensor_id = Column(String(64), ForeignKey("network_sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    source_technology = Column(String(32), nullable=False, index=True)  # ZEEK, SURICATA, PCAP_ANALYZER, SIMULATED
    original_event_id = Column(String(128), nullable=True, index=True)  # Zeek conn UID or Suricata flow_id
    
    event_category = Column(
        String(32), nullable=False, index=True
    )  # CONNECTION, DNS, HTTP, TLS, FLOW, ALERT
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    collected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Endpoints & Transport
    source_ip = Column(String(64), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(64), nullable=False, index=True)
    destination_port = Column(Integer, nullable=True, index=True)
    transport_protocol = Column(String(16), nullable=False, default="TCP", index=True)  # TCP, UDP, ICMP
    application_protocol = Column(String(32), nullable=True, index=True)  # HTTP, DNS, TLS, SSH, SMB
    direction = Column(String(16), nullable=False, default="OUTBOUND", index=True)  # OUTBOUND, INBOUND, INTERNAL, LATERAL

    # Metrics
    connection_duration_seconds = Column(Float, nullable=True)
    bytes_source_to_dest = Column(BigInteger, nullable=True)
    bytes_dest_to_source = Column(BigInteger, nullable=True)
    total_bytes = Column(BigInteger, nullable=True, index=True)
    packets_total = Column(Integer, nullable=True)

    # Protocol-Specific Metadata
    dns_query = Column(String(255), nullable=True, index=True)
    dns_query_type = Column(String(16), nullable=True)  # A, AAAA, TXT, MX, CNAME
    dns_response_code = Column(String(32), nullable=True)  # NOERROR, NXDOMAIN, SERVFAIL
    
    tls_sni = Column(String(255), nullable=True, index=True)
    tls_version = Column(String(32), nullable=True)
    http_method = Column(String(16), nullable=True)
    http_host = Column(String(255), nullable=True, index=True)
    http_uri_stem = Column(String(512), nullable=True)  # Sanitized path, strictly no credentials or query secrets

    # Alert Data (if applicable)
    alert_signature = Column(String(255), nullable=True, index=True)
    alert_severity = Column(String(16), nullable=True, index=True)  # LOW, MEDIUM, HIGH, CRITICAL

    # Forensic Integrity & Lineage
    evidence_provenance = Column(
        String(32), nullable=False, default="IMPORTED", index=True
    )  # OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED
    capture_completeness = Column(
        String(16), nullable=False, default="COMPLETE"
    )  # COMPLETE, PARTIAL, INSUFFICIENT
    is_simulated = Column(Boolean, nullable=False, default=False)
    processing_status = Column(String(32), nullable=False, default="processed")
    metadata_json = Column(Text, nullable=True)

    sensor = relationship("NetworkSensor", back_populates="events")
    alert_references = relationship("NetworkAlertReference", back_populates="network_event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_net_events_time_bytes", "timestamp", "total_bytes"),
        Index("ix_net_events_src_dst", "source_ip", "destination_ip"),
        Index("ix_net_events_sensor_orig", "sensor_id", "original_event_id"),
        Index("ix_net_events_category_time", "event_category", "timestamp"),
    )


class NetworkAlertReference(Base):
    """Maps Suricata or Zeek notice alerts to SentinelDLP's unified security alert ecosystem."""

    __tablename__ = "network_alert_references"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    network_event_id = Column(
        String(36),
        ForeignKey("network_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id = Column(
        String(36),
        ForeignKey("security_alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    signature_name = Column(String(255), nullable=False, index=True)
    suricata_sid = Column(Integer, nullable=True, index=True)
    severity_mapping = Column(String(16), nullable=False, index=True)
    evidence_provenance = Column(String(32), nullable=False, default="IMPORTED")
    explanation = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    network_event = relationship("NetworkEvent", back_populates="alert_references")
    security_alert = relationship("SecurityAlert")


class NetworkIngestionJob(Base):
    """Tracks batch or stream ingestion progress, records count, duplicates, and errors."""

    __tablename__ = "network_ingestion_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sensor_id = Column(
        String(64),
        ForeignKey("network_sensors.sensor_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_format = Column(
        String(32), nullable=False, index=True
    )  # ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_SSL, SURICATA_EVE, PCAP
    file_path = Column(String(512), nullable=True)
    start_time = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completion_time = Column(DateTime(timezone=True), nullable=True)
    records_processed = Column(Integer, nullable=False, default=0)
    records_rejected = Column(Integer, nullable=False, default=0)
    duplicate_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    status = Column(
        String(32), nullable=False, default="PENDING", index=True
    )  # PENDING, RUNNING, COMPLETED, FAILED, PARTIAL
    error_summary = Column(Text, nullable=True)

    sensor = relationship("NetworkSensor", back_populates="ingestion_jobs")


class NetworkBaseline(Base):
    """Stores operational baseline thresholds for anomaly comparison."""

    __tablename__ = "network_baselines"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    baseline_id = Column(String(64), unique=True, nullable=False, index=True)
    applicable_source_scope = Column(String(64), nullable=False, default="GLOBAL")
    metric = Column(String(64), nullable=False, index=True)  # OUTBOUND_FLOW_BYTES, CONNECTION_FREQUENCY, etc.
    threshold = Column(Float, nullable=False)
    policy_version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    description = Column(Text, nullable=True)


class ThreatIntelIndicator(Base):
    """Local threat intelligence context: approved allowlists, internal networks, and manual indicators."""

    __tablename__ = "threat_intel_indicators"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_type = Column(String(16), nullable=False, index=True)  # IPV4, DOMAIN, CIDR
    indicator_value = Column(String(255), nullable=False, index=True)
    category = Column(
        String(32), nullable=False, default="SUSPICIOUS", index=True
    )  # MALICIOUS, SUSPICIOUS, DENIED, TRUSTED_ALLOWLIST, INTERNAL_NET
    source_feed = Column(String(64), nullable=False, default="LOCAL_POLICY")
    confidence = Column(String(16), nullable=False, default="HIGH")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    description = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_intel_type_val", "indicator_type", "indicator_value"),
    )
