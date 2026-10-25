/**
 * TypeScript Type Definitions for SentinelDLP Exfiltration Correlation (Phase 6).
 */

export type InvestigationStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'INCONCLUSIVE';

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type EvidenceConfidence = 'LOW' | 'MEDIUM' | 'HIGH';
export type EvidenceCompleteness = 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';
export type EvidenceProvenance = 'OBSERVED' | 'IMPORTED' | 'LAB_SIMULATED' | 'INFERRED';
export type RelationshipType = 'temporal' | 'circumstantial' | 'verified';

export interface TransferEventItem {
  id: string;
  source_endpoint_id: string;
  occurred_at: string;
  collected_at: string;
  direction: string;
  destination_category: string;
  destination_host: string;
  protocol: string;
  byte_count: number;
  verified_file_reference?: string | null;
  trusted_process_reference?: string | null;
  evidence_source: string;
  evidence_provenance: EvidenceProvenance;
  is_simulated: boolean;
  status: string;
  context_data?: string | null;
}

export interface CorrelationRecordItem {
  id: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  score_contribution: number;
  relationship_type: RelationshipType;
  evidence_completeness: EvidenceCompleteness;
  matched_at: string;
  summary: string;
  details_json?: string | null;
}

export interface InvestigationEvidenceLinkItem {
  id: string;
  evidence_type: string;
  evidence_id: string;
  evidence_provenance: EvidenceProvenance;
  relationship_nature: RelationshipType;
  timestamp: string;
  description: string;
  metadata_json?: string | null;
}

export interface ExfiltrationTimelineItem {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  category: 'FILE_ACTIVITY' | 'ARCHIVE_EVENT' | 'OUTBOUND_TRANSFER' | 'RISK_ALERT' | 'CORRELATION_RULE';
  evidence_provenance: EvidenceProvenance;
  relationship_type: RelationshipType;
  severity?: string | null;
  metadata?: Record<string, any>;
}

export interface ExfiltrationInvestigationItem {
  id: string;
  title: string;
  description: string;
  status: InvestigationStatus;
  risk_score: number;
  severity: RiskSeverity;
  evidence_confidence: EvidenceConfidence;
  evidence_completeness: EvidenceCompleteness;
  primary_endpoint_id?: string | null;
  correlation_window_minutes: number;
  rules_triggered_count: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
  assigned_analyst?: string | null;
  investigation_notes?: string | null;
  correlation_records?: CorrelationRecordItem[];
  evidence_links?: InvestigationEvidenceLinkItem[];
}

export interface ExfiltrationStatistics {
  total_investigations: number;
  open_investigations: number;
  critical_investigations: number;
  high_investigations: number;
  simulated_transfer_count: number;
  rules_active_count: number;
  average_risk_score: number;
}

export interface ExfiltrationRuleDefinition {
  rule_id: string;
  name: string;
  version: string;
  description: string;
  score_contribution: number;
  severity_impact: string;
  required_signals: string[];
  relationship_type: string;
}
