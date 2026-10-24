import { LivenessResponse, ReadinessResponse } from '../types/health';
import {
  AuthorizedRoot,
  PaginatedFilesResponse,
  ScanJobSummary,
} from '../types/scanner';

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
