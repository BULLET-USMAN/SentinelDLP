"""Pydantic Schemas for Network Monitoring and Threat Intelligence (Phase 7).

Strictly isolates sensitive network data: packet payloads and raw credentials are never accepted or emitted.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NetworkSensorResponse(BaseModel):
    """Network sensor metadata and health status."""
    id: str
    sensor_id: str
    technology: str
    version: Optional[str]
    configuration_reference: Optional[str]
    enabled: bool
    last_import_at: Optional[datetime]
    health_status: str
    coverage_gap_reason: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkEventResponse(BaseModel):
    """Normalized network telemetry event."""
    id: str
    sensor_id: str
    source_technology: str
    original_event_id: Optional[str]
    event_category: str
    timestamp: datetime
    collected_at: datetime
    source_ip: str
    source_port: Optional[int]
    destination_ip: str
    destination_port: Optional[int]
    transport_protocol: str
    application_protocol: Optional[str]
    direction: str
    connection_duration_seconds: Optional[float]
    bytes_source_to_dest: Optional[int]
    bytes_dest_to_source: Optional[int]
    total_bytes: Optional[int]
    packets_total: Optional[int]
    dns_query: Optional[str]
    dns_query_type: Optional[str]
    dns_response_code: Optional[str]
    tls_sni: Optional[str]
    tls_version: Optional[str]
    http_method: Optional[str]
    http_host: Optional[str]
    http_uri_stem: Optional[str]
    alert_signature: Optional[str]
    alert_severity: Optional[str]
    evidence_provenance: str
    capture_completeness: str
    is_simulated: bool
    processing_status: str

    model_config = ConfigDict(from_attributes=True)


class PaginatedNetworkEventsResponse(BaseModel):
    """Paginated list of normalized network events."""
    items: List[NetworkEventResponse]
    total: int
    limit: int
    offset: int


class NetworkAlertReferenceResponse(BaseModel):
    """Correlated IDS alert record."""
    id: str
    network_event_id: str
    alert_id: Optional[str]
    signature_name: str
    suricata_sid: Optional[int]
    severity_mapping: str
    evidence_provenance: str
    explanation: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkIngestionJobResponse(BaseModel):
    """Batch ingestion job execution status."""
    id: str
    sensor_id: str
    source_format: str
    file_path: Optional[str]
    start_time: datetime
    completion_time: Optional[datetime]
    records_processed: int
    records_rejected: int
    duplicate_count: int
    error_count: int
    status: str
    error_summary: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class NetworkStatisticsResponse(BaseModel):
    """KPI metrics for Network Intelligence Dashboard."""
    total_connections: int
    outbound_bytes_total: int
    dns_queries_total: int
    ids_alerts_total: int
    active_sensors_count: int
    visibility_gaps_count: int
    top_protocol: str


class TrafficSummaryPoint(BaseModel):
    """Time-series traffic volume data point."""
    timestamp: datetime
    bytes_outbound: int
    connection_count: int


class TrafficSummaryResponse(BaseModel):
    """Traffic volume trend over time."""
    interval: str  # 1h, 24h, 7d
    points: List[TrafficSummaryPoint]
    total_bytes: int


class TopDestinationItem(BaseModel):
    """Top destination endpoint with volume and threat intel flags."""
    destination: str
    connection_count: int
    total_bytes: int
    category: str  # TRUSTED, SUSPICIOUS, UNKNOWN, MALICIOUS
    has_alerts: bool
    first_seen: datetime
    last_seen: datetime


class DNSIntelligenceItem(BaseModel):
    """Aggregated DNS query metrics and anomaly indicators."""
    query_name: str
    query_count: int
    query_types: List[str]
    nxdomain_count: int
    is_anomalous: bool
    anomaly_reason: Optional[str]


class DNSIntelligenceResponse(BaseModel):
    """DNS analytics overview."""
    total_queries: int
    anomalous_queries_count: int
    frequent_domains: List[DNSIntelligenceItem]


class NetworkRuleDefinitionResponse(BaseModel):
    """Specification of an active network detection rule."""
    rule_id: str
    name: str
    version: str
    description: str
    severity_impact: str
    required_events: List[str]
    relationship_type: str


class NetworkIngestRequest(BaseModel):
    """Request payload to trigger offline log ingestion from preapproved path."""
    sensor_id: str = Field(..., max_length=64)
    source_format: str = Field(..., max_length=32)  # ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_SSL, SURICATA_EVE, PCAP
    file_path: Optional[str] = Field(None, max_length=512)
    raw_content: Optional[str] = None  # Direct log text content for API-based submission


class NetworkIngestResponse(BaseModel):
    """Summary of executed ingestion job."""
    job_id: str
    sensor_id: str
    source_format: str
    records_processed: int
    records_rejected: int
    duplicate_count: int
    status: str
    timestamp: datetime


class NetworkSimulateRequest(BaseModel):
    """Trigger synthetic test scenario generation."""
    scenario_type: str = Field(default="mixed_traffic")  # normal_traffic, high_outbound, dns_tunnel_anomaly, suricata_alert, mixed_traffic


class ThreatIntelIndicatorCreate(BaseModel):
    """Add local indicator to threat intel allowlist or blocklist."""
    indicator_type: str = Field(..., max_length=16)  # IPV4, DOMAIN, CIDR
    indicator_value: str = Field(..., max_length=255)
    category: str = Field(default="SUSPICIOUS", max_length=32)
    source_feed: str = Field(default="LOCAL_POLICY", max_length=64)
    confidence: str = Field(default="HIGH", max_length=16)
    description: Optional[str] = None


class ThreatIntelIndicatorResponse(BaseModel):
    """Structured threat intelligence indicator."""
    id: str
    indicator_type: str
    indicator_value: str
    category: str
    source_feed: str
    confidence: str
    expires_at: Optional[datetime]
    created_at: datetime
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class NormalizedNetworkEvent(BaseModel):
    """Internal normalized data structure emitted by parser adapters."""
    sensor_id: str
    source_technology: str
    original_event_id: Optional[str] = None
    event_category: str
    timestamp: datetime
    source_ip: str
    source_port: Optional[int] = None
    destination_ip: str
    destination_port: Optional[int] = None
    transport_protocol: str = "TCP"
    application_protocol: Optional[str] = None
    direction: str = "OUTBOUND"
    connection_duration_seconds: Optional[float] = None
    bytes_source_to_dest: Optional[int] = None
    bytes_dest_to_source: Optional[int] = None
    total_bytes: Optional[int] = None
    packets_total: Optional[int] = None
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_response_code: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_uri_stem: Optional[str] = None
    alert_signature: Optional[str] = None
    alert_severity: Optional[str] = None
    evidence_provenance: str = "IMPORTED"
    capture_completeness: str = "COMPLETE"
    is_simulated: bool = False
    metadata_json: Optional[str] = None
