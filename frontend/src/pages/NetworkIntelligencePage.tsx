import React, { useEffect, useState, useCallback } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Filter,
  FlaskConical,
  Globe,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UploadCloud,
  WifiOff,
  X,
} from 'lucide-react';
import {
  createThreatIntelIndicator,
  fetchIngestionJobs,
  fetchNetworkAlerts,
  fetchNetworkConnections,
  fetchNetworkDNS,
  fetchNetworkRules,
  fetchNetworkSensors,
  fetchNetworkStatistics,
  fetchNetworkStatus,
  fetchTopDestinations,
  fetchThreatIntelIndicators,
  fetchTrafficSummary,
  ingestNetworkTelemetry,
  simulateNetworkScenario,
} from '../services/api';
import {
  DNSIntelligenceItem,
  DNSIntelligenceResponse,
  NetworkAlertItem,
  NetworkEventItem,
  NetworkIngestionJobItem,
  NetworkRuleDefinition,
  NetworkSensorItem,
  NetworkStatistics,
  NetworkStatusResponse,
  ThreatIntelIndicatorCreate,
  ThreatIntelIndicatorItem,
  TopDestinationItem,
  TrafficSummaryPoint,
} from '../types/network';

export const NetworkIntelligencePage: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<
    'traffic' | 'destinations' | 'dns' | 'alerts' | 'sensors'
  >('traffic');

  // Operational states
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Status & Statistics
  const [status, setStatus] = useState<NetworkStatusResponse | null>(null);
  const [statistics, setStatistics] = useState<NetworkStatistics | null>(null);

  // Traffic & Connections tab states
  const [trafficInterval, setTrafficInterval] = useState<'1h' | '24h' | '7d'>('24h');
  const [trafficPoints, setTrafficPoints] = useState<TrafficSummaryPoint[]>([]);
  const [connections, setConnections] = useState<NetworkEventItem[]>([]);
  const [connectionsTotal, setConnectionsTotal] = useState<number>(0);
  const [connectionsPage, setConnectionsPage] = useState<number>(0);
  const connectionsLimit = 25;

  // Connection filters
  const [srcIpFilter, setSrcIpFilter] = useState<string>('');
  const [dstIpFilter, setDstIpFilter] = useState<string>('');
  const [protoFilter, setProtoFilter] = useState<string>('');
  const [minBytesFilter, setMinBytesFilter] = useState<string>('');

  // Top Destinations & Threat Intel tab states
  const [destinations, setDestinations] = useState<TopDestinationItem[]>([]);
  const [indicators, setIndicators] = useState<ThreatIntelIndicatorItem[]>([]);
  const [showAddIndicatorModal, setShowAddIndicatorModal] = useState<boolean>(false);
  const [newIndicator, setNewIndicator] = useState<ThreatIntelIndicatorCreate>({
    indicator_type: 'IPV4',
    indicator_value: '',
    category: 'SUSPICIOUS',
    source_feed: 'LOCAL_ANALYST',
    confidence: 'HIGH',
    description: '',
  });

  // DNS tab states
  const [dnsData, setDnsData] = useState<DNSIntelligenceResponse | null>(null);

  // Alerts & Rules tab states
  const [networkAlerts, setNetworkAlerts] = useState<NetworkAlertItem[]>([]);
  const [rules, setRules] = useState<NetworkRuleDefinition[]>([]);

  // Sensors & Ingestion Jobs tab states
  const [sensors, setSensors] = useState<NetworkSensorItem[]>([]);
  const [ingestionJobs, setIngestionJobs] = useState<NetworkIngestionJobItem[]>([]);
  const [showIngestModal, setShowIngestModal] = useState<boolean>(false);
  const [ingestPayload, setIngestPayload] = useState<{
    sensor_id: string;
    source_format: string;
    raw_content: string;
  }>({
    sensor_id: 'zeek-sensor-01',
    source_format: 'ZEEK_JSON',
    raw_content: '',
  });
  const [ingesting, setIngesting] = useState<boolean>(false);

  // Event Inspector Slide-out Drawer
  const [selectedEvent, setSelectedEvent] = useState<NetworkEventItem | null>(null);

  // Data Loading Callbacks
  const loadStatusAndStats = useCallback(async () => {
    try {
      const [st, stat] = await Promise.all([
        fetchNetworkStatus(),
        fetchNetworkStatistics(),
      ]);
      setStatus(st);
      setStatistics(stat);
    } catch (err: any) {
      console.error('Failed to load status/stats:', err);
    }
  }, []);

  const loadTrafficAndConnections = useCallback(async () => {
    try {
      const [summary, connRes] = await Promise.all([
        fetchTrafficSummary(trafficInterval),
        fetchNetworkConnections({
          source_ip: srcIpFilter.trim() || undefined,
          destination_ip: dstIpFilter.trim() || undefined,
          transport_protocol: protoFilter || undefined,
          min_bytes: minBytesFilter ? parseInt(minBytesFilter, 10) : undefined,
          limit: connectionsLimit,
          offset: connectionsPage * connectionsLimit,
        }),
      ]);
      setTrafficPoints(summary.points || []);
      setConnections(connRes.items || []);
      setConnectionsTotal(connRes.total || 0);
    } catch (err: any) {
      console.error('Failed to load traffic/connections:', err);
    }
  }, [trafficInterval, srcIpFilter, dstIpFilter, protoFilter, minBytesFilter, connectionsPage]);

  const loadDestinationsAndIntel = useCallback(async () => {
    try {
      const [topDests, indList] = await Promise.all([
        fetchTopDestinations(15),
        fetchThreatIntelIndicators(50),
      ]);
      setDestinations(topDests || []);
      setIndicators(indList || []);
    } catch (err: any) {
      console.error('Failed to load destinations/intel:', err);
    }
  }, []);

  const loadDNS = useCallback(async () => {
    try {
      const res = await fetchNetworkDNS(20);
      setDnsData(res);
    } catch (err: any) {
      console.error('Failed to load DNS intelligence:', err);
    }
  }, []);

  const loadAlertsAndRules = useCallback(async () => {
    try {
      const [alts, rls] = await Promise.all([
        fetchNetworkAlerts(50),
        fetchNetworkRules(),
      ]);
      setNetworkAlerts(alts || []);
      setRules(rls || []);
    } catch (err: any) {
      console.error('Failed to load alerts/rules:', err);
    }
  }, []);

  const loadSensorsAndJobs = useCallback(async () => {
    try {
      const [snrs, jobs] = await Promise.all([
        fetchNetworkSensors(),
        fetchIngestionJobs(25),
      ]);
      setSensors(snrs || []);
      setIngestionJobs(jobs || []);
    } catch (err: any) {
      console.error('Failed to load sensors/jobs:', err);
    }
  }, []);

  const refreshAllData = useCallback(async () => {
    setRefreshing(true);
    setErrorMessage(null);
    try {
      await Promise.all([
        loadStatusAndStats(),
        activeTab === 'traffic' && loadTrafficAndConnections(),
        activeTab === 'destinations' && loadDestinationsAndIntel(),
        activeTab === 'dns' && loadDNS(),
        activeTab === 'alerts' && loadAlertsAndRules(),
        activeTab === 'sensors' && loadSensorsAndJobs(),
      ]);
    } catch (err: any) {
      setErrorMessage(err.message || 'Error refreshing network telemetry');
    } finally {
      setRefreshing(false);
    }
  }, [
    activeTab,
    loadStatusAndStats,
    loadTrafficAndConnections,
    loadDestinationsAndIntel,
    loadDNS,
    loadAlertsAndRules,
    loadSensorsAndJobs,
  ]);

  // Initial and tab-switch loader
  useEffect(() => {
    refreshAllData();
  }, [refreshAllData]);

  // Auto-refresh interval (10s)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      refreshAllData();
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, refreshAllData]);

  // Scenario Simulation Handler
  const handleSimulateScenario = async (scenarioType: string) => {
    setSimulating(true);
    setErrorMessage(null);
    try {
      const res = await simulateNetworkScenario(scenarioType);
      setActionSuccessMsg(
        `Simulation completed: Ingested ${res.records_processed} events into ${res.sensor_id}. Rules triggered: ${
          res.rules_triggered.length ? res.rules_triggered.join(', ') : 'None (Benign baseline)'
        }`
      );
      await refreshAllData();
      setTimeout(() => setActionSuccessMsg(null), 8000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to simulate scenario');
    } finally {
      setSimulating(false);
    }
  };

  // Direct Ingest Handler
  const handleIngestTelemetry = async () => {
    if (!ingestPayload.raw_content.trim()) {
      setErrorMessage('Please provide raw log content or JSON data to ingest.');
      return;
    }
    setIngesting(true);
    setErrorMessage(null);
    try {
      const res = await ingestNetworkTelemetry({
        sensor_id: ingestPayload.sensor_id,
        source_format: ingestPayload.source_format,
        raw_content: ingestPayload.raw_content,
      });
      setShowIngestModal(false);
      setIngestPayload((prev) => ({ ...prev, raw_content: '' }));
      setActionSuccessMsg(
        `Ingested ${res.records_processed} events (${res.duplicate_count} deduplicated, ${res.error_count} errors). Status: ${res.status}`
      );
      await refreshAllData();
      setTimeout(() => setActionSuccessMsg(null), 8000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Ingestion failed');
    } finally {
      setIngesting(false);
    }
  };

  // Add Threat Intel Indicator Handler
  const handleCreateIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.indicator_value.trim()) return;
    try {
      await createThreatIntelIndicator(newIndicator);
      setShowAddIndicatorModal(false);
      setNewIndicator({
        indicator_type: 'IPV4',
        indicator_value: '',
        category: 'SUSPICIOUS',
        source_feed: 'LOCAL_ANALYST',
        confidence: 'HIGH',
        description: '',
      });
      setActionSuccessMsg('Threat intel indicator added successfully.');
      await loadDestinationsAndIntel();
      setTimeout(() => setActionSuccessMsg(null), 5000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to add indicator');
    }
  };

  // Helper Formatters
  const formatBytes = (bytes?: number | null): string => {
    if (bytes === undefined || bytes === null || isNaN(bytes)) return '0 B';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatTimestamp = (ts?: string | null): string => {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return ts;
    }
  };

  const getCategoryBadge = (cat?: string) => {
    switch (cat) {
      case 'MALICIOUS':
        return 'bg-red-500/15 text-red-400 border border-red-500/30';
      case 'SUSPICIOUS':
        return 'bg-amber-500/15 text-amber-400 border border-amber-500/30';
      case 'TRUSTED':
        return 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30';
      case 'UNKNOWN':
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700';
    }
  };

  const getSeverityBadge = (sev?: string | null) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-300 border border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
      case 'LOW':
      default:
        return 'bg-blue-500/20 text-blue-300 border border-blue-500/40';
    }
  };

  const getDirectionBadge = (dir?: string) => {
    switch (dir) {
      case 'OUTBOUND':
        return 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30';
      case 'INBOUND':
        return 'bg-purple-500/10 text-purple-400 border border-purple-500/30';
      case 'INTERNAL':
      case 'LATERAL':
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  // Max value calculation for traffic chart visualization
  const maxTrafficBytes = Math.max(...trafficPoints.map((p) => p.bytes_outbound), 1024);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-cyan-600/30 to-blue-600/20 border border-cyan-500/40 rounded-xl text-cyan-400 shadow-sm shadow-cyan-950">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-white tracking-tight">
                  Network Intelligence & Threat Monitoring
                </h1>
                <span className="px-2 py-0.5 text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full">
                  Phase 7 Live
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Zeek & Suricata Telemetry · Offline PCAP Ingestion · Network Detection Engine (NET-001–NET-010)
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls Header */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Simulate Telemetry Dropdown */}
          <div className="relative group">
            <button
              disabled={simulating}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600/80 hover:bg-amber-500 text-white rounded-lg text-xs font-medium transition disabled:opacity-50 border border-amber-500/40 shadow-sm"
            >
              <FlaskConical className={`w-3.5 h-3.5 ${simulating ? 'animate-spin' : ''}`} />
              Simulate Telemetry
            </button>
            <div className="absolute right-0 mt-1 w-64 bg-slate-900 border border-slate-800 rounded-lg shadow-xl py-1 z-30 hidden group-hover:block">
              <div className="px-3 py-1.5 text-[11px] font-semibold text-slate-400 border-b border-slate-800">
                SCENARIOS & ATTACK VECTORS
              </div>
              <button
                onClick={() => handleSimulateScenario('zeek_cloud_upload')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-200">Zeek Cloud Upload</div>
                  <div className="text-[10px] text-slate-400">Triggers NET-001 & NET-008</div>
                </div>
                <span className="text-[10px] text-amber-400 font-mono">18.5 MB</span>
              </button>
              <button
                onClick={() => handleSimulateScenario('suricata_signature_alert')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-200">Suricata Signature Alert</div>
                  <div className="text-[10px] text-slate-400">Triggers NET-007 (SID 2028101)</div>
                </div>
                <span className="text-[10px] text-red-400 font-mono">CRITICAL</span>
              </button>
              <button
                onClick={() => handleSimulateScenario('dns_tunneling_burst')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-200">DNS Tunneling Anomaly</div>
                  <div className="text-[10px] text-slate-400">Triggers NET-004 & NET-005</div>
                </div>
                <span className="text-[10px] text-cyan-400 font-mono">25 Qs</span>
              </button>
              <button
                onClick={() => handleSimulateScenario('benign_baseline')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-200">Benign Internal Traffic</div>
                  <div className="text-[10px] text-slate-400">Normal RFC 1918 telemetry</div>
                </div>
                <span className="text-[10px] text-emerald-400 font-mono">Clean</span>
              </button>
            </div>
          </div>

          {/* Ingest Telemetry Button */}
          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition"
          >
            <UploadCloud className="w-3.5 h-3.5 text-cyan-400" />
            Ingest Telemetry
          </button>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
              autoRefresh
                ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
          >
            {autoRefresh ? 'Auto 10s' : 'Paused'}
          </button>

          {/* Refresh Manual */}
          <button
            onClick={refreshAllData}
            disabled={refreshing}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition disabled:opacity-50"
            title="Refresh Network Data"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action / Error Notification Banners */}
      {actionSuccessMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{actionSuccessMsg}</span>
          </div>
          <button
            onClick={() => setActionSuccessMsg(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {errorMessage && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center justify-between text-xs text-red-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Visibility Gap Diagnostic Warning Banner */}
      {status && status.visibility_gaps_count > 0 && (
        <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-start justify-between text-xs text-amber-200">
          <div className="flex items-start gap-2.5">
            <WifiOff className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-amber-300">
                Network Sensor Diagnostic Warning: {status.visibility_gaps_count} Visibility Gap(s) Reported
              </div>
              <div className="text-slate-300 mt-1">
                {status.visibility_gaps.map((g, idx) => (
                  <span key={idx} className="inline-block mr-3">
                    • <strong className="text-amber-300 font-mono">{g.sensor_id}</strong> ({g.technology}): {g.reason}
                  </span>
                ))}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Note: Container boundary prevents direct promiscuous host packet sniffing without specialized driver hooks.
                Offline log ingestion (Zeek JSON, Suricata EVE, PCAP files) is 100% operational.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top KPI Cards (5 metrics) */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {/* Total Connections */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Connections</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {statistics?.total_connections ?? '—'}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-1">
              Top Protocol: <span className="text-cyan-400 font-mono">{statistics?.top_protocol || 'TCP'}</span>
            </div>
          </div>
        </div>

        {/* Outbound Volume */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Outbound Volume</span>
            <ArrowUpRight className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {formatBytes(statistics?.outbound_bytes_total)}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Normalized flow egress
            </div>
          </div>
        </div>

        {/* DNS Queries */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">DNS Queries</span>
            <Globe className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {statistics?.dns_queries_total ?? '—'}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Entropy & volume tracked
            </div>
          </div>
        </div>

        {/* IDS Alerts */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">IDS Signatures</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {statistics?.ids_alerts_total ?? '—'}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Suricata & Zeek alerts
            </div>
          </div>
        </div>

        {/* Active Sensors */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Sensor Coverage</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white font-mono">
              {statistics?.active_sensors_count ?? 0}
              <span className="text-xs text-slate-500 font-normal ml-1">
                / {status?.sensors_total ?? 4}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {status?.visibility_gaps_count ? (
                <span className="text-amber-400 font-medium">
                  {status.visibility_gaps_count} gap(s) reported
                </span>
              ) : (
                <span className="text-emerald-400">All sensors active</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center border-b border-slate-800 space-x-1 overflow-x-auto pb-px">
        <button
          onClick={() => setActiveTab('traffic')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition whitespace-nowrap ${
            activeTab === 'traffic'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Activity className="w-4 h-4" />
          Traffic & Connections
        </button>

        <button
          onClick={() => setActiveTab('destinations')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition whitespace-nowrap ${
            activeTab === 'destinations'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Globe className="w-4 h-4" />
          Top Destinations & Threat Intel
        </button>

        <button
          onClick={() => setActiveTab('dns')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition whitespace-nowrap ${
            activeTab === 'dns'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Radio className="w-4 h-4" />
          DNS Intelligence
        </button>

        <button
          onClick={() => setActiveTab('alerts')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition whitespace-nowrap ${
            activeTab === 'alerts'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          IDS Alerts & Rules
        </button>

        <button
          onClick={() => setActiveTab('sensors')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition whitespace-nowrap ${
            activeTab === 'sensors'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Server className="w-4 h-4" />
          Sensors & Ingestion Jobs
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: TRAFFIC & CONNECTIONS                                              */}
      {/* ========================================================================= */}
      {activeTab === 'traffic' && (
        <div className="space-y-6">
          {/* Traffic Volume Summary Card & Interactive Chart */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Outbound Network Traffic Volume
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Time-series egress activity normalized across Zeek and Suricata sensor flows
                </p>
              </div>

              {/* Interval Buttons */}
              <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs self-start sm:self-auto">
                <button
                  onClick={() => setTrafficInterval('1h')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    trafficInterval === '1h'
                      ? 'bg-cyan-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  1h
                </button>
                <button
                  onClick={() => setTrafficInterval('24h')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    trafficInterval === '24h'
                      ? 'bg-cyan-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  24h
                </button>
                <button
                  onClick={() => setTrafficInterval('7d')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    trafficInterval === '7d'
                      ? 'bg-cyan-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  7d
                </button>
              </div>
            </div>

            {/* Custom SVG Traffic Bar Chart */}
            <div className="h-44 w-full flex items-end gap-1.5 pt-6 pb-2 px-2 border-b border-slate-800/80 bg-slate-950/40 rounded-lg">
              {trafficPoints.length === 0 ? (
                <div className="w-full h-full flex items-center justify-center text-xs text-slate-500">
                  No outbound traffic recorded in this interval. Trigger telemetry simulation above.
                </div>
              ) : (
                trafficPoints.map((pt, idx) => {
                  const heightPercent = Math.min(
                    100,
                    Math.max(6, Math.round((pt.bytes_outbound / maxTrafficBytes) * 100))
                  );
                  return (
                    <div
                      key={idx}
                      className="flex-1 flex flex-col items-center group relative h-full justify-end"
                    >
                      {/* Tooltip */}
                      <div className="absolute -top-10 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-900 border border-slate-700 text-slate-200 text-[10px] px-2 py-1 rounded shadow-lg whitespace-nowrap z-20 pointer-events-none">
                        <div>{formatTimestamp(pt.timestamp)}</div>
                        <div className="font-mono text-cyan-400">
                          {formatBytes(pt.bytes_outbound)} ({pt.connection_count} conns)
                        </div>
                      </div>

                      {/* Bar */}
                      <div
                        style={{ height: `${heightPercent}%` }}
                        className={`w-full max-w-[28px] rounded-t transition-all ${
                          pt.bytes_outbound > 10 * 1024 * 1024
                            ? 'bg-gradient-to-t from-red-600 to-amber-500 hover:brightness-125'
                            : pt.bytes_outbound > 1024 * 1024
                            ? 'bg-gradient-to-t from-cyan-600 to-blue-400 hover:brightness-125'
                            : 'bg-gradient-to-t from-slate-700 to-slate-500 hover:brightness-125'
                        }`}
                      />
                    </div>
                  );
                })
              )}
            </div>
            <div className="flex justify-between text-[10px] text-slate-500 mt-2 px-1">
              <span>Oldest in Window</span>
              <span>Recent Activity</span>
            </div>
          </div>

          {/* Connection Filter Bar */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5">
                <Search className="w-3.5 h-3.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Source IP..."
                  value={srcIpFilter}
                  onChange={(e) => {
                    setSrcIpFilter(e.target.value);
                    setConnectionsPage(0);
                  }}
                  className="bg-transparent text-slate-200 placeholder-slate-500 text-xs outline-none w-28"
                />
              </div>

              <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5">
                <Search className="w-3.5 h-3.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Dest IP..."
                  value={dstIpFilter}
                  onChange={(e) => {
                    setDstIpFilter(e.target.value);
                    setConnectionsPage(0);
                  }}
                  className="bg-transparent text-slate-200 placeholder-slate-500 text-xs outline-none w-28"
                />
              </div>

              <select
                value={protoFilter}
                onChange={(e) => {
                  setProtoFilter(e.target.value);
                  setConnectionsPage(0);
                }}
                className="bg-slate-950 text-slate-300 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs outline-none"
              >
                <option value="">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>

              <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5">
                <Filter className="w-3.5 h-3.5 text-slate-400" />
                <input
                  type="number"
                  placeholder="Min bytes..."
                  value={minBytesFilter}
                  onChange={(e) => {
                    setMinBytesFilter(e.target.value);
                    setConnectionsPage(0);
                  }}
                  className="bg-transparent text-slate-200 placeholder-slate-500 text-xs outline-none w-24"
                />
              </div>

              {(srcIpFilter || dstIpFilter || protoFilter || minBytesFilter) && (
                <button
                  onClick={() => {
                    setSrcIpFilter('');
                    setDstIpFilter('');
                    setProtoFilter('');
                    setMinBytesFilter('');
                    setConnectionsPage(0);
                  }}
                  className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded text-xs transition"
                >
                  Clear Filters
                </button>
              )}
            </div>

            <div className="text-slate-400 text-xs font-mono">
              Total Flows: <span className="text-white font-bold">{connectionsTotal}</span>
            </div>
          </div>

          {/* Network Connections Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Source (IP:Port)</th>
                    <th className="py-2.5 px-3">Destination (IP:Port)</th>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Direction</th>
                    <th className="py-2.5 px-3">Volume (Tx / Rx)</th>
                    <th className="py-2.5 px-3">Sensor / Provenance</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {connections.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                        No network connections match your filters.
                      </td>
                    </tr>
                  ) : (
                    connections.map((ev) => (
                      <tr
                        key={ev.id}
                        className="hover:bg-slate-800/40 transition group cursor-pointer"
                        onClick={() => setSelectedEvent(ev)}
                      >
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                          {formatTimestamp(ev.timestamp)}
                        </td>
                        <td className="py-2.5 px-3 text-slate-200">
                          {ev.source_ip}
                          {ev.source_port ? `:${ev.source_port}` : ''}
                        </td>
                        <td className="py-2.5 px-3 text-cyan-300 font-medium">
                          {ev.destination_ip}
                          {ev.destination_port ? `:${ev.destination_port}` : ''}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          <span className="px-1.5 py-0.5 bg-slate-800 rounded text-[11px] text-slate-300">
                            {ev.transport_protocol}
                            {ev.application_protocol ? ` / ${ev.application_protocol}` : ''}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-medium ${getDirectionBadge(
                              ev.direction
                            )}`}
                          >
                            {ev.direction}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          <span className="text-white font-medium">
                            {formatBytes(ev.total_bytes)}
                          </span>
                          <span className="text-slate-500 text-[10px] ml-1">
                            ({formatBytes(ev.bytes_source_to_dest)} ↑ / {formatBytes(ev.bytes_dest_to_source)} ↓)
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-[11px] text-slate-400 font-sans">
                            {ev.source_technology}
                          </span>
                          <span className="ml-1 px-1.5 py-0.2 bg-slate-800 text-[10px] rounded text-slate-400">
                            {ev.evidence_provenance}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedEvent(ev);
                            }}
                            className="text-cyan-400 hover:text-cyan-300 font-sans text-xs underline"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {connectionsTotal > connectionsLimit && (
              <div className="flex items-center justify-between p-3 border-t border-slate-800 bg-slate-950/40 text-xs text-slate-400">
                <div>
                  Showing {connectionsPage * connectionsLimit + 1} to{' '}
                  {Math.min((connectionsPage + 1) * connectionsLimit, connectionsTotal)} of{' '}
                  {connectionsTotal} connections
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setConnectionsPage((p) => Math.max(0, p - 1))}
                    disabled={connectionsPage === 0}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded text-xs text-white"
                  >
                    Previous
                  </button>
                  <span className="px-2 font-mono">Page {connectionsPage + 1}</span>
                  <button
                    onClick={() =>
                      setConnectionsPage((p) =>
                        (p + 1) * connectionsLimit < connectionsTotal ? p + 1 : p
                      )
                    }
                    disabled={(connectionsPage + 1) * connectionsLimit >= connectionsTotal}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded text-xs text-white"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: TOP DESTINATIONS & THREAT INTEL                                   */}
      {/* ========================================================================= */}
      {activeTab === 'destinations' && (
        <div className="space-y-6">
          {/* Top Outbound Destinations */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  Top Outbound Destination Hosts & IPs
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Classified against local destination allowlists, threat intelligence, and RFC 1918 internal boundaries
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Destination Host / IP</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Connections</th>
                    <th className="py-2.5 px-3">Egress Volume</th>
                    <th className="py-2.5 px-3">IDS Alerts</th>
                    <th className="py-2.5 px-3">First Seen</th>
                    <th className="py-2.5 px-3">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {destinations.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                        No outbound destinations recorded yet.
                      </td>
                    </tr>
                  ) : (
                    destinations.map((dest, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition">
                        <td className="py-2.5 px-3 text-cyan-300 font-bold">
                          {dest.destination}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-semibold ${getCategoryBadge(
                              dest.category
                            )}`}
                          >
                            {dest.category}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-200">
                          {dest.connection_count}
                        </td>
                        <td className="py-2.5 px-3 text-white font-medium">
                          {formatBytes(dest.total_bytes)}
                        </td>
                        <td className="py-2.5 px-3">
                          {dest.has_alerts ? (
                            <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[10px] font-sans font-medium">
                              IDS Alerted
                            </span>
                          ) : (
                            <span className="text-slate-500 font-sans text-[11px]">—</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {formatTimestamp(dest.first_seen)}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {formatTimestamp(dest.last_seen)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Local Threat Intelligence Context Manager */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Local Threat Intelligence Indicators (Privacy-First Offline Registry)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Preconfigured local IP/domain indicators. Never queries external cloud APIs to prevent private IP telemetry leaks.
                </p>
              </div>
              <button
                onClick={() => setShowAddIndicatorModal(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium transition"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Local Indicator
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Indicator Value</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Source Feed</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Description</th>
                    <th className="py-2.5 px-3">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {indicators.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                        No threat intelligence indicators configured.
                      </td>
                    </tr>
                  ) : (
                    indicators.map((ind) => (
                      <tr key={ind.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-2.5 px-3 text-slate-400">
                          <span className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px] font-sans">
                            {ind.indicator_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-white font-bold">
                          {ind.indicator_value}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-semibold ${getCategoryBadge(
                              ind.category
                            )}`}
                          >
                            {ind.category}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans text-[11px]">
                          {ind.source_feed}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans text-[11px]">
                          {ind.confidence}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                          {ind.description || '—'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-500 text-[11px]">
                          {formatTimestamp(ind.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: DNS INTELLIGENCE                                                   */}
      {/* ========================================================================= */}
      {activeTab === 'dns' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
              <div className="text-slate-400 text-xs">Total DNS Queries Logged</div>
              <div className="text-2xl font-bold text-white font-mono mt-1">
                {dnsData?.total_queries ?? 0}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Captured across Zeek dns.log and Suricata EVE dns v1/v2 records
              </div>
            </div>

            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
              <div className="text-slate-400 text-xs">Anomalous / Suspicious Queries</div>
              <div className="text-2xl font-bold text-amber-400 font-mono mt-1">
                {dnsData?.anomalous_queries_count ?? 0}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                Flagged for high Shannon entropy (&gt;3.8) or excessive label length (&gt;52 chars)
              </div>
            </div>
          </div>

          {/* Frequent / Flagged Domains Table */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-cyan-400" />
                  DNS Query Analysis & Shannon Entropy Anomaly Profiling
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Detection rules NET-004 (Unusual Frequency) and NET-005 (DNS Pattern Anomalies)
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Queried Domain</th>
                    <th className="py-2.5 px-3">Query Count</th>
                    <th className="py-2.5 px-3">Query Types</th>
                    <th className="py-2.5 px-3">NXDOMAIN</th>
                    <th className="py-2.5 px-3">Anomaly Assessment</th>
                    <th className="py-2.5 px-3">Detection Rule Match</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {!dnsData?.frequent_domains?.length ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-500 font-sans">
                        No DNS queries captured in recent telemetry.
                      </td>
                    </tr>
                  ) : (
                    dnsData.frequent_domains.map((d: DNSIntelligenceItem, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition">
                        <td className="py-2.5 px-3 text-cyan-300 font-bold max-w-xs truncate">
                          {d.query_name}
                        </td>
                        <td className="py-2.5 px-3 text-white">
                          {d.query_count}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {d.query_types.map((t, tidx) => (
                            <span
                              key={tidx}
                              className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px] mr-1"
                            >
                              {t}
                            </span>
                          ))}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {d.nxdomain_count > 0 ? (
                            <span className="text-amber-400 font-bold">
                              {d.nxdomain_count}
                            </span>
                          ) : (
                            <span className="text-slate-500">0</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          {d.is_anomalous ? (
                            <span className="px-2 py-0.5 bg-red-500/15 text-red-400 border border-red-500/30 rounded text-[10px] font-sans font-medium">
                              {d.anomaly_reason || 'High Entropy Anomaly'}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded text-[10px] font-sans font-medium">
                              Normal
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                          {d.is_anomalous ? (
                            <span className="text-amber-300 font-mono">NET-005 (Entropy)</span>
                          ) : d.query_count > 20 ? (
                            <span className="text-amber-300 font-mono">NET-004 (Frequency)</span>
                          ) : (
                            '—'
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: IDS ALERTS & RULES                                                 */}
      {/* ========================================================================= */}
      {activeTab === 'alerts' && (
        <div className="space-y-6">
          {/* Normalized IDS Alerts Table */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  Suricata IDS Signatures & Zeek Notices
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Normalized IDS alerts with rule mappings and explanation metadata
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Time</th>
                    <th className="py-2.5 px-3">Signature Name</th>
                    <th className="py-2.5 px-3">Suricata SID</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Provenance</th>
                    <th className="py-2.5 px-3">Explanation & Rule Impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {networkAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-500 font-sans">
                        No IDS alerts recorded. Trigger "Suricata Signature Alert" simulation above to test.
                      </td>
                    </tr>
                  ) : (
                    networkAlerts.map((alt) => (
                      <tr key={alt.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {formatTimestamp(alt.created_at)}
                        </td>
                        <td className="py-2.5 px-3 text-red-300 font-bold">
                          {alt.signature_name}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {alt.suricata_sid ? (
                            <span className="px-1.5 py-0.5 bg-slate-800 rounded text-cyan-400">
                              SID:{alt.suricata_sid}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-bold ${getSeverityBadge(
                              alt.severity_mapping
                            )}`}
                          >
                            {alt.severity_mapping}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                          {alt.evidence_provenance}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans text-[11px] max-w-md">
                          {alt.explanation || 'Mapped via detection rule NET-007'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Active Network Detection Rules Catalog (NET-001 through NET-010) */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  Active Network Detection Rules Catalog (NET-001 — NET-010)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  10 defensive detection rules registered in the SentinelDLP detection pipeline
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {rules.map((rule) => (
                <div
                  key={rule.rule_id}
                  className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-cyan-400 text-xs font-bold">
                      {rule.rule_id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${getSeverityBadge(
                        rule.severity_impact
                      )}`}
                    >
                      {rule.severity_impact}
                    </span>
                  </div>
                  <div className="text-sm font-semibold text-white mt-1">
                    {rule.name}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    {rule.description}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 mt-2 pt-2 border-t border-slate-900 text-[11px] text-slate-500">
                    <span>
                      Events:{' '}
                      <strong className="text-slate-300">
                        {rule.required_events.join(', ')}
                      </strong>
                    </span>
                    <span>•</span>
                    <span>
                      Type:{' '}
                      <strong className="text-slate-300">
                        {rule.relationship_type}
                      </strong>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: SENSORS & INGESTION JOBS                                           */}
      {/* ========================================================================= */}
      {activeTab === 'sensors' && (
        <div className="space-y-6">
          {/* Registered Sensors Cards */}
          <div>
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Registered Network Sensors & Health Auditing
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {sensors.map((s) => (
                <div
                  key={s.id}
                  className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-cyan-400">
                        {s.sensor_id}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          s.health_status === 'ACTIVE'
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : s.health_status === 'VISIBILITY_GAP'
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-red-500/15 text-red-400 border border-red-500/30'
                        }`}
                      >
                        {s.health_status}
                      </span>
                    </div>
                    <div className="text-sm font-semibold text-white mt-2">
                      {s.technology}
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      Version: {s.version || 'Offline / Log Ingest'}
                    </div>
                    {s.coverage_gap_reason && (
                      <div className="mt-2 text-[11px] text-amber-300 bg-amber-950/30 border border-amber-800/40 rounded p-2">
                        {s.coverage_gap_reason}
                      </div>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between">
                    <span>Enabled: {s.enabled ? 'Yes' : 'No'}</span>
                    <span>Last Import: {formatTimestamp(s.last_import_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Ingestion Jobs Audit Table */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Network Ingestion Jobs Audit Trail
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Audit logs for batch Zeek JSON, Suricata EVE, and PCAP header parsing operations
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-2.5 px-3">Start Time</th>
                    <th className="py-2.5 px-3">Sensor ID</th>
                    <th className="py-2.5 px-3">Format</th>
                    <th className="py-2.5 px-3">Processed</th>
                    <th className="py-2.5 px-3">Rejected</th>
                    <th className="py-2.5 px-3">Deduplicated</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Error / Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {ingestionJobs.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-6 text-center text-slate-500 font-sans">
                        No ingestion jobs recorded.
                      </td>
                    </tr>
                  ) : (
                    ingestionJobs.map((j) => (
                      <tr key={j.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {formatTimestamp(j.start_time)}
                        </td>
                        <td className="py-2.5 px-3 text-cyan-300 font-bold">
                          {j.sensor_id}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          <span className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px]">
                            {j.source_format}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-emerald-400 font-bold">
                          {j.records_processed}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">
                          {j.records_rejected}
                        </td>
                        <td className="py-2.5 px-3 text-amber-400">
                          {j.duplicate_count}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-semibold ${
                              j.status === 'COMPLETED'
                                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                : j.status === 'PARTIAL'
                                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                                : 'bg-red-500/15 text-red-400 border border-red-500/30'
                            }`}
                          >
                            {j.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                          {j.error_summary || 'Ingestion completed successfully'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SLIDE-OUT EVENT INSPECTOR DRAWER                                         */}
      {/* ========================================================================= */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 shadow-2xl flex flex-col justify-between">
            <div>
              {/* Drawer Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="p-2 bg-cyan-600/20 text-cyan-400 rounded-lg">
                    <Activity className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">
                      Normalized Network Event
                    </h3>
                    <div className="text-xs text-slate-400 font-mono">
                      Event ID: {selectedEvent.id.substring(0, 18)}...
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Event Attributes Grid */}
              <div className="mt-4 space-y-4 text-xs font-mono">
                {/* 5-Tuple Box */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                  <div className="text-[11px] font-sans font-semibold text-slate-400 mb-2">
                    NETWORK FLOW 5-TUPLE
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Source</span>
                      <span className="text-slate-200">
                        {selectedEvent.source_ip}:{selectedEvent.source_port || '—'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Destination</span>
                      <span className="text-cyan-300 font-bold">
                        {selectedEvent.destination_ip}:{selectedEvent.destination_port || '—'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Protocol</span>
                      <span className="text-slate-200">
                        {selectedEvent.transport_protocol}
                        {selectedEvent.application_protocol ? ` (${selectedEvent.application_protocol})` : ''}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Direction</span>
                      <span className="text-slate-200">{selectedEvent.direction}</span>
                    </div>
                  </div>
                </div>

                {/* Metrics Box */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                  <div className="text-[11px] font-sans font-semibold text-slate-400 mb-2">
                    VOLUME & DURATION
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Total Bytes</span>
                      <span className="text-white font-bold">
                        {formatBytes(selectedEvent.total_bytes)}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Packets</span>
                      <span className="text-slate-300">{selectedEvent.packets_total ?? '—'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Source → Dest</span>
                      <span className="text-slate-300">
                        {formatBytes(selectedEvent.bytes_source_to_dest)}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Dest → Source</span>
                      <span className="text-slate-300">
                        {formatBytes(selectedEvent.bytes_dest_to_source)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Application Metadata Box */}
                {(selectedEvent.dns_query ||
                  selectedEvent.tls_sni ||
                  selectedEvent.http_host ||
                  selectedEvent.alert_signature) && (
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                    <div className="text-[11px] font-sans font-semibold text-slate-400 mb-2">
                      APPLICATION LAYER & IDS METADATA
                    </div>
                    {selectedEvent.dns_query && (
                      <div className="mb-1.5">
                        <span className="text-slate-500 block text-[10px]">DNS Query</span>
                        <span className="text-purple-300 break-all">{selectedEvent.dns_query}</span>
                      </div>
                    )}
                    {selectedEvent.tls_sni && (
                      <div className="mb-1.5">
                        <span className="text-slate-500 block text-[10px]">TLS SNI</span>
                        <span className="text-cyan-300">{selectedEvent.tls_sni}</span>
                      </div>
                    )}
                    {selectedEvent.http_host && (
                      <div className="mb-1.5">
                        <span className="text-slate-500 block text-[10px]">HTTP Host & Path</span>
                        <span className="text-slate-300">
                          {selectedEvent.http_method || 'GET'} {selectedEvent.http_host}
                          {selectedEvent.http_uri_stem || '/'}
                        </span>
                      </div>
                    )}
                    {selectedEvent.alert_signature && (
                      <div className="p-2 bg-red-950/40 border border-red-800/40 rounded mt-2">
                        <span className="text-red-400 font-bold block text-[10px]">
                          ALERT SIGNATURE ({selectedEvent.alert_severity})
                        </span>
                        <span className="text-red-300">{selectedEvent.alert_signature}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Provenance Box */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                  <div className="text-[11px] font-sans font-semibold text-slate-400 mb-2">
                    SENSOR LINEAGE & PROVENANCE
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-slate-300">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Sensor ID</span>
                      <span>{selectedEvent.sensor_id}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Provenance</span>
                      <span>{selectedEvent.evidence_provenance}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Capture</span>
                      <span>{selectedEvent.capture_completeness}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Timestamp</span>
                      <span>{selectedEvent.timestamp}</span>
                    </div>
                  </div>
                </div>

                {/* Privacy Guarantee Note */}
                <div className="p-3 bg-cyan-950/20 border border-cyan-800/30 rounded-lg text-slate-400 font-sans text-[11px] flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Defensive Privacy Guarantee:</strong> Zero raw payload contents are captured or stored in the database.
                    Network ingestion parses only transport headers and high-level protocol indicators.
                  </div>
                </div>
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: ADD THREAT INTEL INDICATOR                                         */}
      {/* ========================================================================= */}
      {showAddIndicatorModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-md p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                Add Local Threat Intel Indicator
              </h3>
              <button
                onClick={() => setShowAddIndicatorModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateIndicator} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Indicator Type
                </label>
                <select
                  value={newIndicator.indicator_type}
                  onChange={(e) =>
                    setNewIndicator({
                      ...newIndicator,
                      indicator_type: e.target.value as 'IPV4' | 'DOMAIN' | 'CIDR',
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none"
                >
                  <option value="IPV4">IPv4 Address</option>
                  <option value="DOMAIN">Domain Name</option>
                  <option value="CIDR">CIDR Subnet</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Indicator Value
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.42 or exfil-drop.com"
                  value={newIndicator.indicator_value}
                  onChange={(e) =>
                    setNewIndicator({
                      ...newIndicator,
                      indicator_value: e.target.value,
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Category
                </label>
                <select
                  value={newIndicator.category}
                  onChange={(e) =>
                    setNewIndicator({
                      ...newIndicator,
                      category: e.target.value,
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none"
                >
                  <option value="MALICIOUS">MALICIOUS (High Alert)</option>
                  <option value="SUSPICIOUS">SUSPICIOUS (Investigate)</option>
                  <option value="TRUSTED">TRUSTED (Corporate Allowlist)</option>
                  <option value="UNKNOWN">UNKNOWN</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Description / Context
                </label>
                <input
                  type="text"
                  placeholder="e.g. Suspected external drop point identified by SOC"
                  value={newIndicator.description}
                  onChange={(e) =>
                    setNewIndicator({
                      ...newIndicator,
                      description: e.target.value,
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800 mt-4">
                <button
                  type="button"
                  onClick={() => setShowAddIndicatorModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium"
                >
                  Save Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: INGEST TELEMETRY DIRECT                                            */}
      {/* ========================================================================= */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-lg p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <UploadCloud className="w-4 h-4 text-cyan-400" />
                Ingest Network Log Content
              </h3>
              <button
                onClick={() => setShowIngestModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Sensor ID
                  </label>
                  <select
                    value={ingestPayload.sensor_id}
                    onChange={(e) =>
                      setIngestPayload({
                        ...ingestPayload,
                        sensor_id: e.target.value,
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none"
                  >
                    <option value="zeek-sensor-01">zeek-sensor-01</option>
                    <option value="suricata-sensor-01">suricata-sensor-01</option>
                    <option value="pcap-analyzer-01">pcap-analyzer-01</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Format
                  </label>
                  <select
                    value={ingestPayload.source_format}
                    onChange={(e) =>
                      setIngestPayload({
                        ...ingestPayload,
                        source_format: e.target.value,
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none"
                  >
                    <option value="ZEEK_JSON">Zeek JSON (conn/dns/http/ssl)</option>
                    <option value="SURICATA_EVE_JSON">Suricata EVE JSON</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Raw Log Lines / JSON Array
                </label>
                <textarea
                  rows={8}
                  placeholder='{"ts": 1729864200.0, "uid": "Cabc123", "id.orig_h": "192.168.1.50", "id.resp_h": "198.51.100.2", "proto": "tcp", "orig_bytes": 1024, "resp_bytes": 2048} ...'
                  value={ingestPayload.raw_content}
                  onChange={(e) =>
                    setIngestPayload({
                      ...ingestPayload,
                      raw_content: e.target.value,
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none font-mono text-[11px]"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800 mt-4">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleIngestTelemetry}
                  disabled={ingesting}
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium"
                >
                  {ingesting ? 'Ingesting...' : 'Start Ingestion'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default NetworkIntelligencePage;
