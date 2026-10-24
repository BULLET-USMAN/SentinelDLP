/**
 * TypeScript Type Definitions for SentinelDLP Risk Intelligence & Security Alerts (Phase 5).
 */

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export type EvidenceCompleteness = 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';

export type DetectionConfidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface RuleMatchItem {
  id?: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  score_contribution: number;
  severity_impact: RiskSeverity;
  match_timestamp: string;
  evidence_data?: Record<string, any>;
}

export interface RiskAssessmentItem {
  id: string;
  event_id: string;
  root_id: string;
  associated_file_id?: string | null;
  risk_score: number;
  severity: RiskSeverity;
  evidence_completeness: EvidenceCompleteness;
  detection_confidence: DetectionConfidence;
  scoring_policy_version: string;
  assessment_status: string;
  explanation: string;
  limitations?: string | null;
  recommended_action?: string | null;
  assessed_at: string;
  rule_matches: RuleMatchItem[];
  alert_id?: string | null;
}

export interface AlertAuditLogItem {
  id: string;
  alert_id: string;
  previous_status: string;
  new_status: string;
  action: string;
  analyst_notes?: string | null;
  performed_by: string;
  performed_at: string;
}

export interface SecurityAlertItem {
  id: string;
  assessment_id: string;
  root_id: string;
  title: string;
  description: string;
  severity: RiskSeverity;
  risk_score: number;
  status: AlertStatus;
  deduplication_key: string;
  repeat_count: number;
  recommended_action?: string | null;
  created_at: string;
  updated_at: string;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
  resolution_notes?: string | null;
}

export interface SecurityAlertDetail extends SecurityAlertItem {
  assessment?: RiskAssessmentItem | null;
  audit_logs: AlertAuditLogItem[];
}

export interface RiskStatistics {
  total_assessments: number;
  low_count: number;
  medium_count: number;
  high_count: number;
  critical_count: number;
  average_score: number;
  score_distribution: {
    '0-29': number;
    '30-59': number;
    '60-79': number;
    '80-100': number;
  };
}

export interface AlertStatistics {
  total_alerts: number;
  open_count: number;
  acknowledged_count: number;
  investigating_count: number;
  resolved_count: number;
  false_positive_count: number;
  by_severity: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
}

export interface DetectionRuleCatalogItem {
  rule_id: string;
  name: string;
  description: string;
  enabled: boolean;
  version: string;
  window_minutes?: number | null;
  base_points: number;
  explanation_template: string;
}

export interface PaginatedRiskAssessments {
  items: RiskAssessmentItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface PaginatedSecurityAlerts {
  items: SecurityAlertItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}
