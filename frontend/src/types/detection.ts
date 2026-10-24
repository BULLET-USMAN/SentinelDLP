export interface DetectionRuleInfo {
  id: string;
  name: string;
  category: string;
  confidence: string;
  suggested_classification: string;
  description: string;
}

export interface FindingItem {
  id: string;
  scanned_file_id: string;
  rule_id: string;
  rule_version: string;
  category: string;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  occurrence_count: number;
  detected_at: string;
}

export interface PaginatedFindingsResponse {
  items: FindingItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface FileClassificationItem {
  id: string;
  scanned_file_id: string;
  sensitivity_label: 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'NOT_ASSESSED';
  policy_version: string;
  inspection_status: string;
  explanation: string;
  highest_confidence: string;
  classified_at: string;
}

export interface ClassifiedFileOverviewItem {
  file_id: string;
  scan_job_id: string;
  filename: string;
  relative_path: string;
  file_extension: string;
  detected_type: string;
  size_bytes: number;
  sensitivity_label: 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'NOT_ASSESSED';
  highest_confidence: string;
  inspection_status: string;
  findings_count: number;
  scan_timestamp: string;
}

export interface PaginatedClassifiedFilesResponse {
  items: ClassifiedFileOverviewItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface FileClassificationDetail {
  file_id: string;
  filename: string;
  relative_path: string;
  detected_type: string;
  size_bytes: number;
  sha256_hash: string | null;
  classification: FileClassificationItem;
  findings: FindingItem[];
}

export interface SensitivitySummaryResponse {
  scan_job_id: string;
  files_inspected: number;
  sensitive_files_count: number;
  public_count: number;
  internal_count: number;
  confidential_count: number;
  restricted_count: number;
  not_assessed_count: number;
  pii_count: number;
  credential_count: number;
  financial_count: number;
  confidential_label_count: number;
  created_at: string;
}
