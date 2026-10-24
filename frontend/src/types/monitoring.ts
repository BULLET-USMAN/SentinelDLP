export interface MonitoringRootInfo {
  root_id: string;
  name: string;
  path: string;
  description: string;
  is_active: boolean;
  session_id: string | null;
}

export interface MonitoringStatusResponse {
  root_id: string;
  status: 'active' | 'stopped' | 'starting' | 'stopping' | 'degraded' | 'failed' | 'configured';
  session_id: string | null;
  started_at: string | null;
  stopped_at: string | null;
  raw_event_count: number;
  processed_event_count: number;
  deduplicated_count: number;
  queue_overflow_count: number;
  last_event_at: string | null;
  last_error: string | null;
}

export interface FileActivityEventItem {
  id: string;
  root_id: string;
  event_type:
    | 'FILE_CREATED'
    | 'FILE_MODIFIED'
    | 'FILE_DELETED'
    | 'FILE_MOVED'
    | 'FILE_RENAMED'
    | 'DIRECTORY_CREATED'
    | 'DIRECTORY_MODIFIED'
    | 'DIRECTORY_DELETED'
    | 'DIRECTORY_MOVED'
    | 'DIRECTORY_RENAMED';
  is_directory: boolean;
  relative_path: string;
  previous_relative_path: string | null;
  occurred_at: string;
  collected_at: string;
  processed_at: string | null;
  status: 'pending' | 'processed' | 'ignored' | 'failed';
  associated_file_id: string | null;
  sensitivity_label: 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'NOT_ASSESSED' | null;
  file_type: string | null;
  size_bytes: number | null;
  sha256_hash: string | null;
  event_source: string;
  error_category: string | null;
}

export interface PaginatedEventsResponse {
  items: FileActivityEventItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface MonitoringStatisticsResponse {
  total_events: number;
  created_count: number;
  modified_count: number;
  deleted_count: number;
  renamed_count: number;
  processed_count: number;
  ignored_count: number;
  failed_count: number;
  active_watchers_count: number;
  queue_backlog: number;
}
