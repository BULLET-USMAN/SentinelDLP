/**
 * TypeScript definitions for Phase 10: Cyberattack Simulation & Detection Validation Laboratory.
 */

export interface ScenarioDefinition {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  target_subsystems: string[];
  mitre_techniques: string[];
  expected_rules: string[];
  expected_alerts: number;
  expected_investigations: number;
  negative_control: boolean;
  estimated_duration_sec: number;
}

export interface ScenarioRunRequest {
  scenario_id: string;
  custom_seed?: number;
  auto_cleanup?: boolean;
}

export interface SimulationStepLog {
  step_number: number;
  action: string;
  status: 'SUCCESS' | 'INFO' | 'WARN' | 'ERROR';
  message: string;
  timestamp: string;
}

export interface SimulationResultResponse {
  id: string;
  run_id: string;
  pass_status: 'PASSED' | 'FAILED' | 'PARTIAL';
  expected_events_count: number;
  actual_events_count: number;
  expected_rules: string[];
  actual_rules: string[];
  matched_rules: string[];
  unmatched_rules: string[];
  unexpected_rules: string[];
  expected_alerts_count: number;
  actual_alerts_count: number;
  expected_investigations_count: number;
  actual_investigations_count: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  latency_ms: number;
  failure_reasons: string[];
}

export interface SimulationRunResponse {
  id: string;
  scenario_id: string;
  scenario_name: string;
  status: 'PENDING' | 'RUNNING' | 'PASSED' | 'FAILED' | 'PARTIAL' | 'ERROR' | 'CANCELLED';
  started_at?: string;
  completed_at?: string;
  duration_ms: number;
  summary?: string;
  execution_logs: SimulationStepLog[];
  result?: SimulationResultResponse;
}

export interface GlobalDetectionMetrics {
  total_runs: number;
  passed_runs: number;
  failed_runs: number;
  partial_runs: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  overall_precision: number;
  overall_recall: number;
  overall_f1: number;
  overall_fpr: number;
  mean_latency_ms: number;
}

export interface SubsystemCoverageItem {
  subsystem: string;
  scenario_id: string;
  scenario_name: string;
  coverage_level: 'SUPPORTED' | 'PARTIALLY_SUPPORTED' | 'NOT_SUPPORTED' | 'NOT_TESTED';
  rules_evaluated: string[];
  notes: string;
}

export interface SimulationReportResponse {
  id: string;
  run_id: string;
  title: string;
  markdown_content: string;
  created_at: string;
}
