import React, { useState, useEffect, useCallback } from 'react';
import {
  HeartPulse,
  Server,
  Database,
  Radio,
  HardDrive,
  ShieldCheck,
  AlertTriangle,
  ArrowUpRight,
  Globe,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  RefreshCw,
  Box,
  Layers,
  Activity,
} from 'lucide-react';
import { fetchLiveness, fetchReadiness, fetchDashboardOverview } from '../services/api';
import { LivenessResponse, ReadinessResponse } from '../types/health';
import { CapabilityHealth } from '../types/dashboard';

export const SystemHealthPage: React.FC = () => {
  const [liveness, setLiveness] = useState<LivenessResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityHealth[]>([]);
  const [freshnessTime, setFreshnessTime] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const checkHealth = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [liveRes, readyRes, overviewRes] = await Promise.allSettled([
        fetchLiveness(),
        fetchReadiness(),
        fetchDashboardOverview(),
      ]);

      if (liveRes.status === 'fulfilled') {
        setLiveness(liveRes.value);
      } else {
        setLiveness(null);
      }

      if (readyRes.status === 'fulfilled') {
        setReadiness(readyRes.value);
      } else {
        setReadiness(null);
      }

      if (overviewRes.status === 'fulfilled') {
        setCapabilities(overviewRes.value.monitoring_status || []);
        setFreshnessTime(overviewRes.value.data_freshness_timestamp || '');
      }

      setLastUpdated(new Date());
    } catch (err: any) {
      setError(err.message || 'Error checking system health');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'HEALTHY':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Healthy
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            Degraded
          </span>
        );
      case 'UNAVAILABLE':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <AlertCircle className="w-3.5 h-3.5" />
            Unavailable
          </span>
        );
      case 'NOT_CONFIGURED':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <HelpCircle className="w-3.5 h-3.5" />
            Not Configured
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            Unknown
          </span>
        );
    }
  };

  const getFreshnessBadge = (freshness: string) => {
    switch (freshness) {
      case 'FRESH':
        return <span className="text-[10px] font-mono text-emerald-400">● Telemetry Fresh</span>;
      case 'STALE':
        return <span className="text-[10px] font-mono text-amber-400">▲ Stale Telemetry</span>;
      default:
        return <span className="text-[10px] font-mono text-slate-500">○ Unavailable</span>;
    }
  };

  const getComponentIcon = (id: string) => {
    switch (id) {
      case 'file_scanner':
        return <HardDrive className="w-5 h-5 text-indigo-400" />;
      case 'filesystem_watchdog':
        return <Radio className="w-5 h-5 text-cyan-400" />;
      case 'sensitive_data_engine':
        return <ShieldCheck className="w-5 h-5 text-emerald-400" />;
      case 'risk_scoring_engine':
        return <AlertTriangle className="w-5 h-5 text-amber-400" />;
      case 'exfiltration_correlation':
        return <ArrowUpRight className="w-5 h-5 text-rose-400" />;
      case 'zeek_network_sensor':
      case 'suricata_ids_sensor':
        return <Globe className="w-5 h-5 text-blue-400" />;
      case 'postgresql_database':
        return <Database className="w-5 h-5 text-emerald-400" />;
      default:
        return <Server className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <HeartPulse className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                System & Sensor Health
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Subsystem observability, container isolation disclosures, telemetry freshness, and database metrics.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500 font-mono hidden sm:inline">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
          <button
            onClick={() => checkHealth()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Health
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Core Runtime Status Banners */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Backend Process Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Server className="w-4 h-4 text-cyan-400" />
              FastAPI Core Process
            </span>
            {liveness ? (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Online
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                Offline
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-slate-300">
            {liveness ? (
              <div>
                Version: <strong className="text-slate-100">{liveness.version}</strong>
                <div className="text-[11px] text-slate-500 mt-0.5">Application: {liveness.app_name}</div>
              </div>
            ) : (
              <div className="text-red-400 text-xs">Unreachable on http://localhost:8000</div>
            )}
          </div>
        </div>

        {/* PostgreSQL Database Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Database className="w-4 h-4 text-emerald-400" />
              PostgreSQL Database
            </span>
            {readiness?.components?.database?.status === 'up' ? (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Operational
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                Degraded
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-slate-300">
            {readiness?.components?.database ? (
              <div>
                Latency:{' '}
                <strong className="text-emerald-400">
                  {readiness.components.database.latency_ms ?? 0} ms
                </strong>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  Pool Status: {readiness.components.database.message || 'Connected'}
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-xs">Waiting for readiness probe...</div>
            )}
          </div>
        </div>

        {/* Platform Readiness Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-purple-400" />
              Overall Readiness
            </span>
            {readiness?.status === 'ready' ? (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Ready
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                Not Ready
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-slate-300">
            Timestamp:{' '}
            <strong className="text-slate-100">
              {freshnessTime ? new Date(freshnessTime).toLocaleTimeString() : 'Current'}
            </strong>
            <div className="text-[11px] text-slate-500 mt-0.5">Defense In-Depth Active</div>
          </div>
        </div>
      </div>

      {/* Container Isolation & Architecture Disclosure */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
        <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
          <Box className="w-4 h-4 text-cyan-400" />
          Container Isolation & Sensor Boundary Disclosure
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          SentinelDLP operates within container boundaries (Docker / Linux). Network sensors (Zeek, Suricata, PCAP
          Analyzer) utilize an offline-first ingestion pipeline for synthetic packet traces and imported captures rather
          than raw host promiscuous sockets. This ensures maximum stability, eliminates raw socket privilege
          escalation vulnerabilities, and preserves clean defense-in-depth isolation in containerized deployment.
        </p>
      </div>

      {/* Subsystem Capability Health Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            Subsystem Capability Health Matrix
          </h2>
          <span className="text-xs text-slate-500 font-mono">{capabilities.length} Sensors & Engines</span>
        </div>

        {capabilities.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">
            Loading subsystem capability matrix...
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {capabilities.map(cap => (
              <div
                key={cap.component_id}
                className="p-4 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between space-y-3"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 rounded bg-slate-900 border border-slate-800">
                        {getComponentIcon(cap.component_id)}
                      </div>
                      <span className="font-semibold text-sm text-slate-200">{cap.name}</span>
                    </div>
                    {getStatusBadge(cap.status)}
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed mt-2">{cap.details}</p>
                </div>

                <div className="pt-3 border-t border-slate-900 flex items-center justify-between text-xs">
                  {getFreshnessBadge(cap.telemetry_freshness)}
                  {cap.last_active && (
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(cap.last_active).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
export default SystemHealthPage;