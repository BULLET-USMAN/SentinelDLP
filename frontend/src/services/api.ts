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
import {
  AlertStatistics,
  AlertStatus,
  DetectionRuleCatalogItem,
  PaginatedRiskAssessments,
  PaginatedSecurityAlerts,
  RiskAssessmentItem,
  RiskStatistics,
  SecurityAlertDetail,
} from '../types/risk';
import {
  ExfiltrationInvestigationItem,
  ExfiltrationRuleDefinition,
  ExfiltrationStatistics,
  ExfiltrationTimelineItem,
  InvestigationStatus,
  TransferEventItem,
} from '../types/exfiltration';

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

// ==========================================
// Phase 5: Risk Intelligence & Security Alerts
// ==========================================

export async function fetchRiskAssessments(
  page: number = 1,
  pageSize: number = 20,
  rootId?: string,
  severity?: string,
  minScore?: number,
  maxScore?: number,
  status?: string,
): Promise<PaginatedRiskAssessments> {
  const params = new URLSearchParams({
    page: page.toString(),
    page_size: pageSize.toString(),
  });
  if (rootId) params.append('root_id', rootId);
  if (severity) params.append('severity', severity);
  if (minScore !== undefined) params.append('min_score', minScore.toString());
  if (maxScore !== undefined) params.append('max_score', maxScore.toString());
  if (status) params.append('status', status);

  const url = `${API_BASE_URL}/api/v1/risk/assessments?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load risk assessments (${response.status})`);
  }
  return response.json();
}

export async function fetchRiskAssessmentDetails(assessmentId: string): Promise<RiskAssessmentItem> {
  const url = `${API_BASE_URL}/api/v1/risk/assessments/${assessmentId}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load assessment details (${response.status})`);
  }
  return response.json();
}

export async function fetchRiskStatistics(): Promise<RiskStatistics> {
  const url = `${API_BASE_URL}/api/v1/risk/statistics`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load risk statistics (${response.status})`);
  }
  return response.json();
}

export async function fetchDetectionRulesCatalog(): Promise<DetectionRuleCatalogItem[]> {
  const url = `${API_BASE_URL}/api/v1/risk/rules`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load detection rules catalog (${response.status})`);
  }
  return response.json();
}

export async function fetchSecurityAlerts(
  page: number = 1,
  pageSize: number = 20,
  status?: string,
  severity?: string,
  rootId?: string,
  minScore?: number,
): Promise<PaginatedSecurityAlerts> {
  const params = new URLSearchParams({
    page: page.toString(),
    page_size: pageSize.toString(),
  });
  if (status) params.append('status', status);
  if (severity) params.append('severity', severity);
  if (rootId) params.append('root_id', rootId);
  if (minScore !== undefined) params.append('min_score', minScore.toString());

  const url = `${API_BASE_URL}/api/v1/alerts?${params.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load security alerts (${response.status})`);
  }
  return response.json();
}

export async function fetchAlertDetails(alertId: string): Promise<SecurityAlertDetail> {
  const url = `${API_BASE_URL}/api/v1/alerts/${alertId}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load alert details (${response.status})`);
  }
  return response.json();
}

export async function updateAlertStatus(
  alertId: string,
  status: AlertStatus,
  analystNotes?: string,
  performedBy: string = 'security_analyst',
): Promise<SecurityAlertDetail> {
  const url = `${API_BASE_URL}/api/v1/alerts/${alertId}/status`;
  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      status,
      analyst_notes: analystNotes || null,
      performed_by: performedBy,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to update alert status (${response.status})`);
  }
  return response.json();
}

export async function fetchAlertStatistics(): Promise<AlertStatistics> {
  const url = `${API_BASE_URL}/api/v1/alerts/statistics`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load alert statistics (${response.status})`);
  }
  return response.json();
}

/* =========================================================================
 * PHASE 6: Data Exfiltration & Event Correlation APIs
 * ========================================================================= */

export async function fetchExfiltrationStatistics(): Promise<ExfiltrationStatistics> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/statistics`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load exfiltration statistics (${response.status})`);
  }
  return response.json();
}

export async function fetchExfiltrationInvestigations(params?: {
  status?: string;
  severity?: string;
  confidence?: string;
  limit?: number;
  offset?: number;
}): Promise<ExfiltrationInvestigationItem[]> {
  const query = new URLSearchParams();
  if (params?.status) query.append('status', params.status);
  if (params?.severity) query.append('severity', params.severity);
  if (params?.confidence) query.append('confidence', params.confidence);
  if (params?.limit) query.append('limit', params.limit.toString());
  if (params?.offset !== undefined) query.append('offset', params.offset.toString());

  const url = `${API_BASE_URL}/api/v1/exfiltration/investigations?${query.toString()}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load exfiltration investigations (${response.status})`);
  }
  return response.json();
}

export async function fetchExfiltrationInvestigationDetail(id: string): Promise<ExfiltrationInvestigationItem> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/investigations/${id}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load investigation details (${response.status})`);
  }
  return response.json();
}

export async function fetchExfiltrationTimeline(id: string): Promise<ExfiltrationTimelineItem[]> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/investigations/${id}/timeline`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load investigation timeline (${response.status})`);
  }
  return response.json();
}

export async function updateExfiltrationInvestigationStatus(
  id: string,
  status: InvestigationStatus,
  assignedAnalyst?: string,
  notes?: string,
): Promise<ExfiltrationInvestigationItem> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/investigations/${id}/status`;
  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      status,
      assigned_analyst: assignedAnalyst || null,
      notes: notes || null,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to update investigation (${response.status})`);
  }
  return response.json();
}

export async function fetchExfiltrationRules(): Promise<ExfiltrationRuleDefinition[]> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/rules`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load exfiltration rules (${response.status})`);
  }
  return response.json();
}

export async function triggerCorrelationRun(windowMinutes: number = 15): Promise<any> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/correlate`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ window_minutes: windowMinutes }),
  });

  if (!response.ok) {
    throw new Error(`Failed to trigger correlation pass (${response.status})`);
  }
  return response.json();
}

export async function simulateTransferScenario(scenarioType: string = 'cloud_exfiltration'): Promise<TransferEventItem[]> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/transfers/simulate?scenario_type=${scenarioType}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to simulate scenario (${response.status})`);
  }
  return response.json();
}

export async function fetchTransferEvents(limit: number = 50): Promise<TransferEventItem[]> {
  const url = `${API_BASE_URL}/api/v1/exfiltration/transfers?limit=${limit}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch transfers (${response.status})`);
  }
  return response.json();
}
