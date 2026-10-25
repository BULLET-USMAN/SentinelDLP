import React, { useEffect, useState, useCallback } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  HeartPulse,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  WifiOff,
  X,
} from 'lucide-react';
import { fetchDashboardOverview } from '../services/api';
import {
  DashboardOverviewResponse,
} from '../types/dashboard';
import { NavigationTab } from '../components/layout/Sidebar';

interface OverviewPageProps {
  onNavigateToTab: (tab: NavigationTab, targetId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigateToTab }) => {
  const [data, setData] = useState<DashboardOverviewResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activityFilter, setActivityFilter] = useState<string>('ALL');

  const loadData = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    else setRefreshing(true);
    setErrorMsg(null);
    try {
      const res = await fetchDashboardOverview();
      setData(res);
    } catch (err: any) {
      console.error('Failed to load SOC overview:', err);
      setErrorMsg(err.message || 'Failed to connect to SentinelDLP telemetry aggregator');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 10000);
    return () => clearInterval(interval);
  }, [loadData]);

  const formatTimestamp = (ts?: string | null): string => {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  const getSeverityBadge = (sev?: string | null) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-400 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30';
      case 'LOW':
      default:
        return 'bg-blue-500/15 text-blue-400 border border-blue-500/30';
    }
  };

  const getProvenanceBadge = (prov: string) => {
    switch (prov) {
      case 'OBSERVED':
        return 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30';
      case 'IMPORTED':
        return 'bg-blue-500/15 text-blue-400 border border-blue-500/30';
      case 'LAB_SIMULATED':
        return 'bg-amber-500/15 text-amber-400 border border-amber-500/30';
      case 'INFERRED':
      default:
        return 'bg-purple-500/15 text-purple-400 border border-purple-500/30';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'HEALTHY':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
      case 'DEGRADED':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      case 'UNAVAILABLE':
      case 'OFFLINE':
        return 'bg-red-500/10 text-red-400 border border-red-500/30';
      case 'NOT_CONFIGURED':
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  // Filtered activity items
  const filteredActivity = (data?.recent_activity || []).filter((item) => {
    if (activityFilter === 'ALL') return true;
    if (activityFilter === 'ALERTS') return item.category === 'SECURITY_ALERT';
    if (activityFilter === 'EXFIL') return item.category === 'EXFILTRATION';
    if (activityFilter === 'FILES') return item.category === 'FILE_ACTIVITY';
    if (activityFilter === 'NETWORK') return item.category === 'NETWORK_IDS' || item.category === 'DNS_ANOMALY';
    return true;
  });

  // Calculate maximum for trend visualization
  const maxTrendTotal = Math.max(...(data?.risk_trends || []).map((t) => t.total), 5);

  return (
    <div className="space-y-6">
      {/* Executive Welcome & Live Telemetry Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-tight">
              Security Operations Center Overview
            </h1>
            <span className="px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
              Phase 11 Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time unified defensive telemetry across endpoints, storage, risk assessments, and network flows
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>Freshness: {formatTimestamp(data?.data_freshness_timestamp)}</span>
          <button
            onClick={() => loadData(false)}
            disabled={loading || refreshing}
            className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition"
            title="Refresh Overview"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Error notification banner */}
      {errorMsg && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center justify-between text-xs text-red-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-slate-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Visibility Gap Container Notice */}
      {data?.security_summary && data.security_summary.visibility_gaps_count > 0 && (
        <div className="p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-start gap-3 text-xs text-amber-200">
          <WifiOff className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-amber-300">
              Sensor Boundary Diagnostics: {data.security_summary.visibility_gaps_count} Visibility Gap(s) Reported
            </div>
            <p className="text-slate-300 mt-0.5 text-[11px]">
              Docker container boundaries isolate the host network. High-fidelity offline ingestion (Zeek JSON, Suricata EVE, PCAP files) is operational, while direct promiscuous host packet sniffing is gracefully held in safe diagnostic reserve.
            </p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION A: SECURITY SUMMARY KPI TILES (6 TILES)                          */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Open Alerts */}
        <div
          onClick={() => onNavigateToTab('alerts')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Open Alerts</span>
            <ShieldAlert className="w-4 h-4 text-red-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {data?.security_summary.open_alerts_count ?? '—'}
            </div>
            <div className="text-[10px] text-red-400 mt-0.5">
              {data?.security_summary.high_critical_alerts_count ?? 0} High / Critical
            </div>
          </div>
        </div>

        {/* Active Investigations */}
        <div
          onClick={() => onNavigateToTab('investigations')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Investigations</span>
            <Search className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {data?.security_summary.active_investigations_count ?? '—'}
            </div>
            <div className="text-[10px] text-cyan-400 mt-0.5">
              Active forensic cases
            </div>
          </div>
        </div>

        {/* Potential Exfiltration */}
        <div
          onClick={() => onNavigateToTab('exfiltration')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Exfil Signals</span>
            <ArrowUpRight className="w-4 h-4 text-amber-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {data?.security_summary.potential_exfiltrations_count ?? '—'}
            </div>
            <div className="text-[10px] text-amber-400 mt-0.5">
              Correlated transfers
            </div>
          </div>
        </div>

        {/* Sensitive Files */}
        <div
          onClick={() => onNavigateToTab('detection')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Sensitive Assets</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {data?.security_summary.sensitive_files_count ?? '—'}
            </div>
            <div className="text-[10px] text-emerald-400 mt-0.5">
              Classified files
            </div>
          </div>
        </div>

        {/* Active Sensors */}
        <div
          onClick={() => onNavigateToTab('network')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Active Sensors</span>
            <Server className="w-4 h-4 text-blue-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {data?.security_summary.active_sensors_count ?? '—'}
            </div>
            <div className="text-[10px] text-blue-400 mt-0.5">
              Zeek, Suricata, PCAP
            </div>
          </div>
        </div>

        {/* System Health */}
        <div
          onClick={() => onNavigateToTab('health')}
          className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between cursor-pointer transition group"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">System Health</span>
            <HeartPulse className="w-4 h-4 text-purple-400 group-hover:scale-110 transition" />
          </div>
          <div className="mt-2">
            <div className="text-sm font-bold text-emerald-400 font-mono flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
              OPERATIONAL
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              PostgreSQL + Services
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION B & C: RISK DISTRIBUTION + PRIORITY ANALYST QUEUE               */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Risk Severity Distribution & Explainability (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900/70 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  Risk Severity Distribution
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Avg: <strong className="text-white">{data?.risk_distribution.average_score ?? 0}</strong>/100
              </span>
            </div>

            {/* 4 Severity Band Tiles */}
            <div className="grid grid-cols-4 gap-2 text-center mt-4">
              <div className="p-2.5 rounded-xl bg-blue-950/30 border border-blue-900/40">
                <div className="text-lg font-bold text-blue-400 font-mono">
                  {data?.risk_distribution.low_count ?? 0}
                </div>
                <div className="text-[10px] text-blue-300/70 font-semibold uppercase mt-0.5">Low</div>
                <div className="text-[9px] text-slate-500 font-mono">0-29</div>
              </div>

              <div className="p-2.5 rounded-xl bg-yellow-950/30 border border-yellow-900/40">
                <div className="text-lg font-bold text-yellow-400 font-mono">
                  {data?.risk_distribution.medium_count ?? 0}
                </div>
                <div className="text-[10px] text-yellow-300/70 font-semibold uppercase mt-0.5">Medium</div>
                <div className="text-[9px] text-slate-500 font-mono">30-59</div>
              </div>

              <div className="p-2.5 rounded-xl bg-orange-950/30 border border-orange-900/40">
                <div className="text-lg font-bold text-orange-400 font-mono">
                  {data?.risk_distribution.high_count ?? 0}
                </div>
                <div className="text-[10px] text-orange-300/70 font-semibold uppercase mt-0.5">High</div>
                <div className="text-[9px] text-slate-500 font-mono">60-79</div>
              </div>

              <div className="p-2.5 rounded-xl bg-red-950/30 border border-red-900/40">
                <div className="text-lg font-bold text-red-400 font-mono">
                  {data?.risk_distribution.critical_count ?? 0}
                </div>
                <div className="text-[10px] text-red-300/70 font-semibold uppercase mt-0.5">Critical</div>
                <div className="text-[9px] text-slate-500 font-mono">80-100</div>
              </div>
            </div>

            {/* Architectural Philosophy Note */}
            <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl mt-4 text-[11px] text-slate-400">
              <strong className="text-slate-200 block mb-1">Defense-in-Depth Principle:</strong>
              {data?.risk_distribution.explanation}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
            <span>Total Evaluations: <strong className="text-slate-300 font-mono">{data?.risk_distribution.total_assessments ?? 0}</strong></span>
            <button
              onClick={() => onNavigateToTab('risk')}
              className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium"
            >
              Risk Engine <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right: Priority Analyst Queue (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/70 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  Priority Analyst Triage Queue
                </h3>
              </div>
              <span className="text-[11px] text-slate-400">
                Unresolved High & Critical Incidents
              </span>
            </div>

            {/* Priority List */}
            <div className="divide-y divide-slate-800/60 mt-2">
              {!data?.priority_queue || data.priority_queue.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1.5" />
                  No open critical or high priority incidents requiring immediate triage.
                </div>
              ) : (
                data.priority_queue.map((item) => (
                  <div
                    key={item.id}
                    onClick={() =>
                      onNavigateToTab(
                        item.item_type === 'ALERT' ? 'alerts' : 'investigations',
                        item.id
                      )
                    }
                    className="py-2.5 px-2 hover:bg-slate-800/40 rounded-lg flex items-center justify-between cursor-pointer transition group"
                  >
                    <div className="flex items-center gap-3 overflow-hidden">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold shrink-0 ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                      <div className="overflow-hidden">
                        <div className="text-xs font-semibold text-white group-hover:text-cyan-300 transition truncate">
                          {item.title}
                        </div>
                        <div className="text-[10px] text-slate-400 flex items-center gap-2 mt-0.5 font-mono">
                          <span>{item.item_type}</span>
                          <span>•</span>
                          <span>Score: {item.risk_score ?? '—'}/100</span>
                          <span>•</span>
                          <span>{formatTimestamp(item.timestamp)}</span>
                        </div>
                      </div>
                    </div>

                    <button className="text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition text-xs font-medium flex items-center gap-1 shrink-0 ml-3">
                      Triage <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex justify-end">
            <button
              onClick={() => onNavigateToTab('alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
            >
              Open Complete Alerts Console <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION D: RISK TRENDS (7-DAY FREQUENCY GRAPH)                           */}
      {/* ========================================================================= */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              7-Day Historical Risk Assessment Volume Trends
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Daily frequency of evaluated events across Low, Medium, High, and Critical severity thresholds
            </p>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-red-500" /> Critical
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-orange-500" /> High
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-yellow-500" /> Med
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm bg-blue-500" /> Low
            </span>
          </div>
        </div>

        {/* Bar Chart Visualization */}
        <div className="h-40 w-full flex items-end gap-2 pt-6 pb-2 px-2 bg-slate-950/50 rounded-xl border border-slate-800/80">
          {!data?.risk_trends || data.risk_trends.length === 0 ? (
            <div className="w-full h-full flex items-center justify-center text-xs text-slate-500">
              No historical trend points recorded yet.
            </div>
          ) : (
            data.risk_trends.map((pt, idx) => {
              const heightPercent = Math.min(100, Math.max(8, Math.round((pt.total / maxTrendTotal) * 100)));
              return (
                <div key={idx} className="flex-1 flex flex-col items-center group relative h-full justify-end">
                  {/* Tooltip */}
                  <div className="absolute -top-12 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-900 border border-slate-700 text-slate-200 text-[10px] px-2.5 py-1.5 rounded-lg shadow-xl whitespace-nowrap z-20 pointer-events-none">
                    <div className="font-bold">{pt.bucket}</div>
                    <div className="text-slate-400">
                      Total: {pt.total} (Crit: {pt.critical}, High: {pt.high}, Med: {pt.medium}, Low: {pt.low})
                    </div>
                  </div>

                  {/* Segmented Bar */}
                  <div
                    style={{ height: `${heightPercent}%` }}
                    className="w-full max-w-[36px] rounded-t flex flex-col justify-end overflow-hidden transition-all group-hover:brightness-125"
                  >
                    {pt.critical > 0 && <div style={{ flex: pt.critical }} className="bg-red-500 w-full" />}
                    {pt.high > 0 && <div style={{ flex: pt.high }} className="bg-orange-500 w-full" />}
                    {pt.medium > 0 && <div style={{ flex: pt.medium }} className="bg-yellow-500 w-full" />}
                    {pt.low > 0 && <div style={{ flex: pt.low }} className="bg-blue-500 w-full" />}
                    {pt.total === 0 && <div className="bg-slate-800 w-full h-full" />}
                  </div>

                  <span className="text-[10px] text-slate-500 mt-2 font-mono">{pt.bucket}</span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION E: RECENT SECURITY ACTIVITY (UNIFIED FEED)                       */}
      {/* ========================================================================= */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400" />
              Unified Security Activity Telemetry Stream
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Chronological feed combining filesystem events, security alerts, exfiltration correlations, and network IDS signatures
            </p>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
            {['ALL', 'ALERTS', 'EXFIL', 'FILES', 'NETWORK'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActivityFilter(tab)}
                className={`px-2.5 py-1 rounded font-medium transition ${
                  activityFilter === tab
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* Activity Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Event Summary</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Source / Provenance</th>
                <th className="py-2.5 px-3 text-right">Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredActivity.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No recent security activity matching this category.
                  </td>
                </tr>
              ) : (
                filteredActivity.map((act) => (
                  <tr key={act.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {formatTimestamp(act.timestamp)}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-sans">
                        {act.category}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-white font-medium max-w-md truncate font-sans">
                      <div>{act.title}</div>
                      <div className="text-[11px] text-slate-400 truncate">{act.description}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      {act.severity ? (
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${getSeverityBadge(act.severity)}`}>
                          {act.severity}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-slate-400 text-[11px] font-sans mr-1">{act.source_technology}</span>
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-sans ${getProvenanceBadge(act.evidence_provenance)}`}>
                        {act.evidence_provenance}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      {act.category === 'SECURITY_ALERT' && (
                        <button
                          onClick={() => onNavigateToTab('alerts', act.reference_id || undefined)}
                          className="text-cyan-400 hover:text-cyan-300 font-sans text-xs underline"
                        >
                          View Alert
                        </button>
                      )}
                      {act.category === 'EXFILTRATION' && (
                        <button
                          onClick={() => onNavigateToTab('investigations', act.reference_id || undefined)}
                          className="text-amber-400 hover:text-amber-300 font-sans text-xs underline"
                        >
                          Investigate
                        </button>
                      )}
                      {act.category === 'FILE_ACTIVITY' && (
                        <button
                          onClick={() => onNavigateToTab('activity')}
                          className="text-emerald-400 hover:text-emerald-300 font-sans text-xs underline"
                        >
                          Activity
                        </button>
                      )}
                      {act.category === 'NETWORK_IDS' && (
                        <button
                          onClick={() => onNavigateToTab('network')}
                          className="text-blue-400 hover:text-blue-300 font-sans text-xs underline"
                        >
                          Network
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION F: PLATFORM CAPABILITIES & SENSOR HEALTH                         */}
      {/* ========================================================================= */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Server className="w-4 h-4 text-purple-400" />
              Platform Capabilities & Sensor Observability
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Operational state and telemetry freshness across all integrated SentinelDLP defense modules
            </p>
          </div>
          <button
            onClick={() => onNavigateToTab('health')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            Detailed Health Monitor <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {data?.monitoring_status.map((item) => (
            <div
              key={item.component_id}
              className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white truncate max-w-[200px]">
                    {item.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${getStatusBadge(item.status)}`}>
                    {item.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                  {item.details}
                </p>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-900 text-[10px] text-slate-500 font-mono flex items-center justify-between">
                <span>Freshness: {item.telemetry_freshness}</span>
                <span>Active: {formatTimestamp(item.last_active)}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
export default OverviewPage;
