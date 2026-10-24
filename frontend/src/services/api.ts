import { LivenessResponse, ReadinessResponse } from '../types/health';
import {
  AuthorizedRoot,
  PaginatedFilesResponse,
  ScanJobSummary,
} from '../types/scanner';
import {
  DetectionRuleInfo,
  FileClassificationDetail,
  PaginatedClassifiedFilesResponse,
  PaginatedFindingsResponse,
  SensitivitySummaryResponse,
} from '../types/detection';
import {
  FileActivityEventItem,
  MonitoringRootInfo,
  MonitoringStatisticsResponse,
  MonitoringStatusResponse,
  PaginatedEventsResponse,
} from '../types/monitoring';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export async function fetchLiveness(): Promise<LivenessResponse> {
  const url = `${API_BASE_URL}/health/live`;
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Liveness check failed with status ${response.status}`);
  }

  return response.json();
}

export async function fetchReadiness(): Promise<ReadinessResponse> {
  const url = `${API_BASE_URL}/health/ready`;
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (response.status === 200 || response.status === 503) {
    return response.json();
  }

  throw new Error(`Readiness probe failed with unexpected HTTP ${response.status}`);
}

// =========================================================================
// Phase 2 Scanner API Calls
// =========================================================================

export async function fetchAuthorizedRoots(): Promise<AuthorizedRoot[]> {
  const url = `${API_BASE_URL}/api/v1/scanner/roots`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load authorized scan roots (${response.status})`);
  }
  return response.json();
}

export async function createScanJob(rootId: string): Promise<ScanJobSummary> {
  const url = `${API_BASE_URL}/api/v1/scans`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ root_id: rootId }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to initiate scan (${response.status})`);
  }

  return response.json();
}

export async function fetchScanHistory(limit: number = 20): Promise<ScanJobSummary[]> {
  const url = `${API_BASE_URL}/api/v1/scans?limit=${limit}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch scan history (${response.status})`);
  }
  return response.json();
}

export async function fetchScanStatus(scanId: string): Promise<ScanJobSummary> {
  const url = `${API_BASE_URL}/api/v1/scans/${scanId}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch status for scan ${scanId} (${response.status})`);
  }
  return response.json();
}

export async function fetchScanFiles(
  scanId: string,
  page: number = 1,
  size: number = 25,
  search?: string,
  fileType?: string,
  status?: string,
  typeMismatch?: boolean
): Promise<PaginatedFilesResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    size: size.toString(),
  });

  if (search) params.append('search', search);
  if (fileType) params.append('file_type', fileType);
  if (status) params.append('status', status);
  if (typeMismatch !== undefined) params.append('type_mismatch', typeMismatch.toString());

  const url = `${API_BASE_URL}/api/v1/scans/${scanId}/files?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load inventory files (${response.status})`);
  }
  return response.json();
}

export async function cancelScanJob(scanId: string): Promise<{ status: string; message: string }> {
  const url = `${API_BASE_URL}/api/v1/scans/${scanId}/cancel`;
  const response = await fetch(url, {
    method: 'POST',
  });
  if (!response.ok) {
    throw new Error(`Failed to cancel scan (${response.status})`);
  }
  return response.json();
}

// =========================================================================
// Phase 3 Detection & Classification API Calls
// =========================================================================

export async function fetchDetectionRules(): Promise<DetectionRuleInfo[]> {
  const url = `${API_BASE_URL}/api/v1/detection/rules`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load detection rules (${response.status})`);
  }
  return response.json();
}

export async function fetchSensitivitySummary(scanId: string): Promise<SensitivitySummaryResponse> {
  const url = `${API_BASE_URL}/api/v1/scans/${scanId}/sensitivity-summary`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load sensitivity summary (${response.status})`);
  }
  return response.json();
}

export async function fetchScanFindings(
  scanId: string,
  page: number = 1,
  size: number = 50,
  category?: string,
  confidence?: string
): Promise<PaginatedFindingsResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    size: size.toString(),
  });
  if (category) params.append('category', category);
  if (confidence) params.append('confidence', confidence);

  const url = `${API_BASE_URL}/api/v1/scans/${scanId}/findings?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load findings (${response.status})`);
  }
  return response.json();
}

export async function fetchClassifiedFiles(
  scanId: string,
  page: number = 1,
  size: number = 25,
  sensitivity?: string,
  category?: string,
  search?: string,
  highestConfidence?: string
): Promise<PaginatedClassifiedFilesResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    size: size.toString(),
  });
  if (sensitivity) params.append('sensitivity', sensitivity);
  if (category) params.append('category', category);
  if (search) params.append('search', search);
  if (highestConfidence) params.append('highest_confidence', highestConfidence);

  const url = `${API_BASE_URL}/api/v1/scans/${scanId}/classified-files?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load classified files (${response.status})`);
  }
  return response.json();
}

export async function fetchFileClassificationDetail(fileId: string): Promise<FileClassificationDetail> {
  const url = `${API_BASE_URL}/api/v1/files/${fileId}/classification`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load file classification detail (${response.status})`);
  }
  return response.json();
}

// =========================================================================
// Phase 4 Real-Time File Activity Monitoring API Calls
// =========================================================================

export async function fetchMonitoringRoots(): Promise<MonitoringRootInfo[]> {
  const url = `${API_BASE_URL}/api/v1/monitoring/roots`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load monitoring roots (${response.status})`);
  }
  return response.json();
}

export async function fetchMonitoringStatus(rootId?: string): Promise<MonitoringStatusResponse> {
  const params = rootId ? `?root_id=${encodeURIComponent(rootId)}` : '';
  const url = `${API_BASE_URL}/api/v1/monitoring/status${params}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch monitoring status (${response.status})`);
  }
  return response.json();
}

export async function startMonitoring(rootId: string, recursive: boolean = true): Promise<MonitoringStatusResponse> {
  const url = `${API_BASE_URL}/api/v1/monitoring/start`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ root_id: rootId, recursive }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to start monitoring (${response.status})`);
  }
  return response.json();
}

export async function stopMonitoring(rootId: string): Promise<MonitoringStatusResponse> {
  const url = `${API_BASE_URL}/api/v1/monitoring/stop`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ root_id: rootId }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to stop monitoring (${response.status})`);
  }
  return response.json();
}

export async function fetchMonitoringEvents(
  page: number = 1,
  size: number = 50,
  rootId?: string,
  eventType?: string,
  sensitivity?: string,
  search?: string,
  status?: string
): Promise<PaginatedEventsResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    size: size.toString(),
  });
  if (rootId) params.append('root_id', rootId);
  if (eventType) params.append('event_type', eventType);
  if (sensitivity) params.append('sensitivity', sensitivity);
  if (search) params.append('search', search);
  if (status) params.append('status', status);

  const url = `${API_BASE_URL}/api/v1/monitoring/events?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load activity events (${response.status})`);
  }
  return response.json();
}

export async function fetchEventDetails(eventId: string): Promise<FileActivityEventItem> {
  const url = `${API_BASE_URL}/api/v1/monitoring/events/${eventId}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load event details (${response.status})`);
  }
  return response.json();
}

export async function fetchMonitoringStatistics(rootId?: string): Promise<MonitoringStatisticsResponse> {
  const params = rootId ? `?root_id=${encodeURIComponent(rootId)}` : '';
  const url = `${API_BASE_URL}/api/v1/monitoring/statistics${params}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch monitoring statistics (${response.status})`);
  }
  return response.json();
}

export function createEventSourceStream(rootId: string = 'synthetic_samples'): EventSource {
  const url = `${API_BASE_URL}/api/v1/monitoring/events/stream?root_id=${encodeURIComponent(rootId)}`;
  return new EventSource(url);
}
