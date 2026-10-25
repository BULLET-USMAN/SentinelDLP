/**
 * TypeScript Type Definitions for SentinelDLP Centralized SOC Dashboard (Phase 8).
 */

export interface SecuritySummary {
  open_alerts_count: number;
  high_critical_alerts_count: number;
  active_investigations_count: number;
  potential_exfiltrations_count: number;
  sensitive_files_count: number;
  active_sensors_count: number;
  visibility_gaps_count: number;
}

export interface RiskDistributionSummary {
  low_count: number;
  medium_count: number;
  high_count: number;
  critical_count: number;
  average_score: number;
  total_assessments: number;
  explanation: string;
}

export interface RecentActivityItem {
  id: string;
  timestamp: string;
  category: 'FILE_ACTIVITY' | 'SECURITY_ALERT' | 'RISK_ASSESSMENT' | 'EXFILTRATION' | 'NETWORK_IDS' | 'DNS_ANOMALY';
  title: string;
  description: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  source_technology: string;
  evidence_provenance: 'OBSERVED' | 'IMPORTED' | 'LAB_SIMULATED' | 'INFERRED';
  reference_id?: string | null;
}

export interface RiskTrendPoint {
  bucket: string;
  low: number;
  medium: number;
  high: number;
  critical: number;
  total: number;
}

export interface CapabilityHealth {
  component_id: string;
  name: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | 'NOT_CONFIGURED' | 'UNKNOWN';
  details: string;
  telemetry_freshness: 'FRESH' | 'STALE' | 'UNAVAILABLE';
  last_active?: string | null;
}

export interface PriorityQueueItem {
  id: string;
  item_type: 'ALERT' | 'INVESTIGATION';
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score?: number | null;
  status: string;
  timestamp: string;
  rule_name?: string | null;
  analyst?: string | null;
  reference_url?: string | null;
}

export interface DashboardOverviewResponse {
  security_summary: SecuritySummary;
  risk_distribution: RiskDistributionSummary;
  recent_activity: RecentActivityItem[];
  risk_trends: RiskTrendPoint[];
  monitoring_status: CapabilityHealth[];
  priority_queue: PriorityQueueItem[];
  data_freshness_timestamp: string;
  coverage_completeness: string;
}

export interface SearchResultItem {
  result_type: 'ALERT' | 'INVESTIGATION' | 'FILE' | 'INDICATOR' | 'RULE';
  id: string;
  title: string;
  subtitle: string;
  metadata: Record<string, any>;
  link_tab: string;
  link_id?: string | null;
}

export interface DashboardSearchResponse {
  query: string;
  total_results: number;
  results: SearchResultItem[];
}
