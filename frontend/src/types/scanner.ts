export interface AuthorizedRoot {
  root_id: string;
  name: string;
  path: string;
  description: string;
}

export interface ScanJobSummary {
  id: string;
  root_id: string;
  root_path: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  started_at: string;
  completed_at: string | null;
  files_discovered: number;
  files_processed: number;
  files_skipped: number;
  error_count: number;
  total_bytes_processed: number;
  duration_seconds: number | null;
  error_message: string | null;
}

export interface ScannedFileItem {
  id: string;
  scan_job_id: string;
  filename: string;
  relative_path: string;
  file_extension: string;
  detected_type: string;
  size_bytes: number;
  created_at: string | null;
  modified_at: string | null;
  sha256_hash: string | null;
  scan_timestamp: string;
  status: 'scanned' | 'skipped' | 'error';
  error_message: string | null;
  type_mismatch: boolean;
}

export interface PaginatedFilesResponse {
  items: ScannedFileItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}
