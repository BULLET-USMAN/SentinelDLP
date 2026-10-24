import { LivenessResponse, ReadinessResponse } from '../types/health';

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

  // Note: /health/ready returns 503 when dependencies like DB are down,
  // but it still returns a valid JSON payload containing component diagnostics.
  if (response.status === 200 || response.status === 503) {
    return response.json();
  }

  throw new Error(`Readiness probe failed with unexpected HTTP ${response.status}`);
}
