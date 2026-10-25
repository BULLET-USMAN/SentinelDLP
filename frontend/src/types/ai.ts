/**
 * TypeScript Type Definitions for SentinelDLP AI-Powered SOC Analyst (Phase 9).
 */

export type ConfidenceAssessment =
  | 'STRONG_SUPPORT'
  | 'PARTIAL_SUPPORT'
  | 'LIMITED_SUPPORT'
  | 'INSUFFICIENT_EVIDENCE';

export type EvidenceCompleteness = 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';

export type AnalystReviewStatus = 'PENDING' | 'USEFUL' | 'INCORRECT' | 'NEEDS_REVIEW';

export interface ObservedFactItem {
  fact: string;
  record_id?: string | null;
  source_technology: string;
  provenance: string;
}

export interface MitreAttackMappingItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  justification: string;
  confidence: string;
}

export interface AIInvestigationReportResponse {
  id: string;
  investigation_id?: string | null;
  alert_id?: string | null;
  model_id: string;
  provider_type: string;
  status: string;
  executive_summary: string;
  assessment: string;
  confidence_assessment: ConfidenceAssessment;
  evidence_completeness: EvidenceCompleteness;
  observed_facts: ObservedFactItem[];
  possible_explanations: string[];
  missing_evidence: string[];
  recommended_actions: string[];
  mitre_attack_mappings: MitreAttackMappingItem[];
  evidence_references: string[];
  tool_calls_count: number;
  prompt_template_version: string;
  report_schema_version: string;
  analyst_review_status: AnalystReviewStatus;
  analyst_feedback_notes?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  created_at: string;
  execution_duration_ms: number;
}

export interface ChatMessageResponse {
  message_id: string;
  session_id: string;
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  evidence_references: string[];
  tool_invocations: Array<Record<string, any>>;
  created_at: string;
}

export interface ConversationSessionSummary {
  id: string;
  investigation_id?: string | null;
  alert_id?: string | null;
  title: string;
  status: string;
  model_id: string;
  message_count: number;
  created_at: string;
  updated_at: string;
}

export interface ConversationSessionDetail {
  id: string;
  investigation_id?: string | null;
  alert_id?: string | null;
  title: string;
  status: string;
  model_id: string;
  messages: ChatMessageResponse[];
  created_at: string;
  updated_at: string;
}

export interface AIModelInfo {
  model_id: string;
  provider: string;
  download_size_approx: string;
  vram_requirement_approx: string;
  supports_tool_calling: boolean;
  supports_json_schema: boolean;
  is_active: boolean;
  description: string;
}

export interface AIStatusResponse {
  provider_type: string;
  model_id: string;
  is_healthy: boolean;
  details: string;
  active_features: string[];
  safety_guardrails: string[];
  model_storage_location: string;
  available_models: AIModelInfo[];
}
