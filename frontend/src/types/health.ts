export interface LivenessResponse {
  status: string;
  app_name: string;
  version: string;
  timestamp: string;
}

export interface ComponentHealth {
  status: 'up' | 'down';
  message?: string;
  latency_ms?: number;
}

export interface ReadinessResponse {
  status: 'ready' | 'unready';
  app_name: string;
  version: string;
  timestamp: string;
  components: Record<string, ComponentHealth>;
}

export interface SystemStatusState {
  liveness: LivenessResponse | null;
  readiness: ReadinessResponse | null;
  isLoading: boolean;
  error: string | null;
  lastChecked: Date | null;
}
