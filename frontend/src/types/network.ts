/**
 * TypeScript Type Definitions for SentinelDLP Network Intelligence (Phase 7).
 */

export interface NetworkSensorItem {
  id: string;
  sensor_id: string;
  technology: 'ZEEK' | 'SURICATA' | 'PCAP_ANALYZER' | 'SIMULATED';
  version?: string | null;
  configuration_reference?: string | null;
  enabled: boolean;
  last_import_at?: string | null;
  health_status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE' | 'VISIBILITY_GAP';
  coverage_gap_reason?: string | null;
  created_at: string;
}

export interface NetworkEventItem {
  id: string;
  sensor_id: string;
  source_technology: string;
  original_event_id?: string | null;
  event_category: 'CONNECTION' | 'DNS' | 'HTTP' | 'TLS' | 'FLOW' | 'ALERT';
  timestamp: string;
  collected_at: string;
  source_ip: string;
  source_port?: number | null;
  destination_ip: string;
  destination_port?: number | null;
  transport_protocol: string;
  application_protocol?: string | null;
  direction: 'OUTBOUND' | 'INBOUND' | 'INTERNAL' | 'LATERAL';
  connection_duration_seconds?: number | null;
  bytes_source_to_dest?: number | null;
  bytes_dest_to_source?: number | null;
  total_bytes?: number | null;
  packets_total?: number | null;
  dns_query?: string | null;
  dns_query_type?: string | null;
  dns_response_code?: string | null;
  tls_sni?: string | null;
  tls_version?: string | null;
  http_method?: string | null;
  http_host?: string | null;
  http_uri_stem?: string | null;
  alert_signature?: string | null;
  alert_severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  evidence_provenance: string;
  capture_completeness: string;
  is_simulated: boolean;
  processing_status: string;
}

export interface NetworkAlertItem {
  id: string;
  network_event_id: string;
  alert_id?: string | null;
  signature_name: string;
  suricata_sid?: number | null;
  severity_mapping: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence_provenance: string;
  explanation?: string | null;
  created_at: string;
}

export interface NetworkIngestionJobItem {
  id: string;
  sensor_id: string;
  source_format: string;
  file_path?: string | null;
  start_time: string;
  completion_time?: string | null;
  records_processed: number;
  records_rejected: number;
  duplicate_count: number;
  error_count: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL';
  error_summary?: string | null;
}

export interface NetworkStatistics {
  total_connections: number;
  outbound_bytes_total: number;
  dns_queries_total: number;
  ids_alerts_total: number;
  active_sensors_count: number;
  visibility_gaps_count: number;
  top_protocol: string;
}

export interface TrafficSummaryPoint {
  timestamp: string;
  bytes_outbound: number;
  connection_count: number;
}

export interface TrafficSummaryResponse {
  interval: string;
  points: TrafficSummaryPoint[];
  total_bytes: number;
}

export interface TopDestinationItem {
  destination: string;
  connection_count: number;
  total_bytes: number;
  category: 'TRUSTED' | 'SUSPICIOUS' | 'UNKNOWN' | 'MALICIOUS';
  has_alerts: boolean;
  first_seen: string;
  last_seen: string;
}

export interface DNSIntelligenceItem {
  query_name: string;
  query_count: number;
  query_types: string[];
  nxdomain_count: number;
  is_anomalous: boolean;
  anomaly_reason?: string | null;
}

export interface DNSIntelligenceResponse {
  total_queries: number;
  anomalous_queries_count: number;
  frequent_domains: DNSIntelligenceItem[];
}

export interface NetworkRuleDefinition {
  rule_id: string;
  name: string;
  version: string;
  description: string;
  severity_impact: string;
  required_events: string[];
  relationship_type: string;
}

export interface ThreatIntelIndicatorItem {
  id: string;
  indicator_type: 'IPV4' | 'DOMAIN' | 'CIDR';
  indicator_value: string;
  category: string;
  source_feed: string;
  confidence: string;
  expires_at?: string | null;
  created_at: string;
  description?: string | null;
}

export interface PaginatedNetworkEventsResponse {
  items: NetworkEventItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface VisibilityGapItem {
  sensor_id: string;
  technology: string;
  reason?: string | null;
}

export interface NetworkStatusResponse {
  status: 'operational' | 'degraded';
  sensors_active: number;
  sensors_total: number;
  visibility_gaps_count: number;
  visibility_gaps: VisibilityGapItem[];
  timestamp: string;
}

export interface NetworkIngestResponse {
  job_id: string;
  sensor_id: string;
  source_format: string;
  records_processed: number;
  records_rejected: number;
  duplicate_count: number;
  error_count: number;
  status: string;
  rules_triggered: string[];
}

export interface ThreatIntelIndicatorCreate {
  indicator_type: 'IPV4' | 'DOMAIN' | 'CIDR';
  indicator_value: string;
  category?: string;
  source_feed?: string;
  confidence?: string;
  description?: string;
}
