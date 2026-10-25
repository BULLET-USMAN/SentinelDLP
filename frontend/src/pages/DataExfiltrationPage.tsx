import React, { useEffect, useState, useCallback } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Filter,
  RefreshCw,
  Sliders,
  X,
  History,
  Activity,
  Network,
  FileArchive,
  FileText,
  Clock,
  ArrowUpRight,
  FlaskConical,
  Send,
} from 'lucide-react';
import {
  fetchExfiltrationInvestigationDetail,
  fetchExfiltrationInvestigations,
  fetchExfiltrationRules,
  fetchExfiltrationStatistics,
  fetchExfiltrationTimeline,
  fetchTransferEvents,
  simulateTransferScenario,
  triggerCorrelationRun,
  updateExfiltrationInvestigationStatus,
} from '../services/api';
import {
  ExfiltrationInvestigationItem,
  ExfiltrationRuleDefinition,
  ExfiltrationStatistics,
  ExfiltrationTimelineItem,
  InvestigationStatus,
  RiskSeverity,
  TransferEventItem,
} from '../types/exfiltration';

export const DataExfiltrationPage: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'investigations' | 'transfers' | 'rules'>('investigations');

  // Operational states
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [correlationRunning, setCorrelationRunning] = useState<boolean>(false);
  const [correlationWindow, setCorrelationWindow] = useState<number>(15);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Statistics
  const [statistics, setStatistics] = useState<ExfiltrationStatistics | null>(null);

  // Investigations & filters
  const [investigations, setInvestigations] = useState<ExfiltrationInvestigationItem[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('');

  // Selected investigation for side drawer
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string | null>(null);
  const [investigationDetail, setInvestigationDetail] = useState<ExfiltrationInvestigationItem | null>(null);
  const [timeline, setTimeline] = useState<ExfiltrationTimelineItem[]>([]);
  const [drawerLoading, setDrawerLoading] = useState<boolean>(false);
  const [triageNotes, setTriageNotes] = useState<string>('');
  const [triageAnalyst, setTriageAnalyst] = useState<string>('sec-analyst');
  const [triageLoading, setTriageLoading] = useState<boolean>(false);

  // Transfers & rules
  const [transfers, setTransfers] = useState<TransferEventItem[]>([]);
  const [rules, setRules] = useState<ExfiltrationRuleDefinition[]>([]);
  const [simulatingScenario, setSimulatingScenario] = useState<boolean>(false);

  // Load KPI stats
  const loadStatistics = useCallback(async () => {
    try {
      const stats = await fetchExfiltrationStatistics();
      setStatistics(stats);
    } catch (err: any) {
      console.error('Failed to load exfiltration stats', err);
    }
  }, []);

  // Load investigations
  const loadInvestigations = useCallback(async () => {
    try {
      const data = await fetchExfiltrationInvestigations({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        confidence: confidenceFilter || undefined,
        limit: 50,
      });
      setInvestigations(data);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to fetch investigations');
    }
  }, [statusFilter, severityFilter, confidenceFilter]);

  // Load transfers
  const loadTransfers = useCallback(async () => {
    try {
      const data = await fetchTransferEvents(50);
      setTransfers(data);
    } catch (err: any) {
      console.error('Failed to fetch transfers', err);
    }
  }, []);

  // Load rules
  const loadRules = useCallback(async () => {
    try {
      const data = await fetchExfiltrationRules();
      setRules(data);
    } catch (err: any) {
      console.error('Failed to fetch rules', err);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadStatistics();
    loadInvestigations();
    loadTransfers();
    loadRules();
  }, [loadStatistics, loadInvestigations, loadTransfers, loadRules]);

  // Auto-refresh interval
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadStatistics();
      if (activeTab === 'investigations') loadInvestigations();
      if (activeTab === 'transfers') loadTransfers();
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, activeTab, loadStatistics, loadInvestigations, loadTransfers]);

  // Handle manual refresh
  const handleRefresh = async () => {
    setRefreshing(true);
    setErrorMessage(null);
    try {
      await Promise.all([loadStatistics(), loadInvestigations(), loadTransfers(), loadRules()]);
    } finally {
      setRefreshing(false);
    }
  };

  // Run Correlation Pass
  const handleRunCorrelation = async () => {
    setCorrelationRunning(true);
    setErrorMessage(null);
    try {
      const res = await triggerCorrelationRun(correlationWindow);
      setActionSuccessMsg(
        `Correlation completed: ${res.investigations_created} investigation(s) created across ${res.window_minutes}m window.`
      );
      await Promise.all([loadStatistics(), loadInvestigations()]);
      setTimeout(() => setActionSuccessMsg(null), 6000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to run correlation');
    } finally {
      setCorrelationRunning(false);
    }
  };

  // Simulate Lab Scenario
  const handleSimulateScenario = async (scenario: string) => {
    setSimulatingScenario(true);
    setErrorMessage(null);
    try {
      const created = await simulateTransferScenario(scenario);
      setActionSuccessMsg(
        `Generated ${created.length} synthetic transfer event(s) tagged [LAB_SIMULATED]. Running correlation...`
      );
      await loadTransfers();
      await handleRunCorrelation();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to simulate scenario');
    } finally {
      setSimulatingScenario(false);
    }
  };

  // Open Investigation Drawer
  const handleSelectInvestigation = async (invId: string) => {
    setSelectedInvestigationId(invId);
    setDrawerLoading(true);
    try {
      const [detail, timelineData] = await Promise.all([
        fetchExfiltrationInvestigationDetail(invId),
        fetchExfiltrationTimeline(invId),
      ]);
      setInvestigationDetail(detail);
      setTimeline(timelineData);
      setTriageNotes('');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load investigation details');
    } finally {
      setDrawerLoading(false);
    }
  };

  // Update Triage Status
  const handleUpdateStatus = async (newStatus: InvestigationStatus) => {
    if (!selectedInvestigationId) return;
    setTriageLoading(true);
    try {
      const updated = await updateExfiltrationInvestigationStatus(
        selectedInvestigationId,
        newStatus,
        triageAnalyst,
        triageNotes
      );
      setInvestigationDetail(updated);
      setTriageNotes('');
      setActionSuccessMsg(`Investigation status transitioned to ${newStatus}`);
      await Promise.all([loadStatistics(), loadInvestigations()]);
      setTimeout(() => setActionSuccessMsg(null), 5000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update investigation status');
    } finally {
      setTriageLoading(false);
    }
  };

  // Color helper functions
  const getSeverityBadge = (severity: RiskSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      case 'LOW':
      default:
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
    }
  };

  const getStatusBadge = (status: InvestigationStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-red-500/15 text-red-300 border-red-500/40';
      case 'ACKNOWLEDGED':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
      case 'INVESTIGATING':
        return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40';
      case 'RESOLVED':
        return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
      case 'FALSE_POSITIVE':
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
      case 'INCONCLUSIVE':
      default:
        return 'bg-purple-500/15 text-purple-300 border-purple-500/40';
    }
  };

  const getProvenanceBadge = (prov: string) => {
    switch (prov) {
      case 'OBSERVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'IMPORTED':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'LAB_SIMULATED':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'INFERRED':
      default:
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
    }
  };

  const getRelationshipBadge = (rel: string) => {
    switch (rel) {
      case 'verified':
        return 'bg-emerald-950 text-emerald-300 border border-emerald-700/50';
      case 'circumstantial':
        return 'bg-indigo-950 text-indigo-300 border border-indigo-700/50';
      case 'temporal':
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Data Exfiltration & Correlation Engine
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              Phase 6 Active
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Temporal security event correlation identifying sensitive file access, staging archives, and outbound transfer telemetry.
          </p>
        </div>

        {/* Global Action Bar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Correlation Window selector */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
            <Clock className="w-3.5 h-3.5 text-slate-400 ml-2 mr-1" />
            <span className="text-slate-400 mr-1">Window:</span>
            <select
              value={correlationWindow}
              onChange={(e) => setCorrelationWindow(Number(e.target.value))}
              className="bg-slate-800 text-slate-200 border-none rounded px-2 py-1 text-xs focus:ring-1 focus:ring-cyan-500 outline-none"
            >
              <option value={1}>1 min</option>
              <option value={5}>5 mins</option>
              <option value={15}>15 mins</option>
              <option value={30}>30 mins</option>
              <option value={60}>60 mins</option>
            </select>
          </div>

          {/* Trigger Correlation Button */}
          <button
            onClick={handleRunCorrelation}
            disabled={correlationRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium transition disabled:opacity-50 shadow-sm shadow-cyan-900/50"
          >
            <Activity className={`w-3.5 h-3.5 ${correlationRunning ? 'animate-spin' : ''}`} />
            {correlationRunning ? 'Correlating...' : 'Run Correlation'}
          </button>

          {/* Lab Scenario Generator Menu */}
          <div className="relative group">
            <button
              disabled={simulatingScenario}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600/80 hover:bg-amber-500 text-white rounded-lg text-xs font-medium transition disabled:opacity-50 border border-amber-500/40"
            >
              <FlaskConical className={`w-3.5 h-3.5 ${simulatingScenario ? 'animate-spin' : ''}`} />
              Simulate Telemetry
            </button>
            <div className="absolute right-0 mt-1 w-56 bg-slate-900 border border-slate-800 rounded-lg shadow-xl py-1 z-30 hidden group-hover:block">
              <div className="px-3 py-1.5 text-[11px] font-semibold text-slate-400 border-b border-slate-800">
                LAB SIMULATED FIXTURES
              </div>
              <button
                onClick={() => handleSimulateScenario('cloud_exfiltration')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <span>Cloud Exfil (mega.nz)</span>
                <span className="text-[10px] text-amber-400 font-mono">18.5 MB</span>
              </button>
              <button
                onClick={() => handleSimulateScenario('chunked_exfiltration')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <span>Chunked Multi-IP</span>
                <span className="text-[10px] text-amber-400 font-mono">4 chunks</span>
              </button>
              <button
                onClick={() => handleSimulateScenario('benign_sync')}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 flex items-center justify-between"
              >
                <span>Authorized Sync</span>
                <span className="text-[10px] text-emerald-400 font-mono">backup</span>
              </button>
            </div>
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
              autoRefresh
                ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
          >
            {autoRefresh ? 'Live Poll On' : 'Live Poll Off'}
          </button>

          {/* Refresh button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Banner Notifications */}
      {actionSuccessMsg && (
        <div className="flex items-center gap-2 p-3 bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 rounded-lg text-xs animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{actionSuccessMsg}</span>
        </div>
      )}
      {errorMessage && (
        <div className="flex items-center gap-2 p-3 bg-red-950/60 border border-red-800/80 text-red-300 rounded-lg text-xs">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage(null)} className="ml-auto text-red-400 hover:text-red-200">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Total Correlated</span>
            <Network className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1">
            {statistics ? statistics.total_investigations : '—'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Bounded correlation records</div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active Triage</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {statistics ? statistics.open_investigations : '—'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Open & Investigating cases</div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Critical / High</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 mt-1">
            {statistics ? statistics.critical_investigations + statistics.high_investigations : '—'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">High severity alerts</div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Lab Telemetry</span>
            <FlaskConical className="w-4 h-4 text-amber-300" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-1">
            {statistics ? statistics.simulated_transfer_count : '—'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Synthetic transfer fixtures</div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active Detection Rules</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">
            {statistics ? statistics.rules_active_count : '8'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">EXFIL-001 through 008</div>
        </div>
      </div>

      {/* Main Tab Navigation */}
      <div className="flex items-center border-b border-slate-800 gap-6 text-sm">
        <button
          onClick={() => setActiveTab('investigations')}
          className={`pb-2.5 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'investigations'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-4 h-4" />
          Correlated Investigations ({investigations.length})
        </button>
        <button
          onClick={() => setActiveTab('transfers')}
          className={`pb-2.5 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'transfers'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ArrowUpRight className="w-4 h-4" />
          Outbound Transfer Telemetry ({transfers.length})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-2.5 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'rules'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Detection Rules Suite ({rules.length})
        </button>
      </div>

      {/* TAB 1: Investigations */}
      {activeTab === 'investigations' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-3 bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400 font-medium">Filter Cases:</span>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-800 text-slate-300 border border-slate-700 rounded px-2.5 py-1 outline-none"
            >
              <option value="">All Triage States</option>
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
              <option value="INCONCLUSIVE">INCONCLUSIVE</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-800 text-slate-300 border border-slate-700 rounded px-2.5 py-1 outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            <select
              value={confidenceFilter}
              onChange={(e) => setConfidenceFilter(e.target.value)}
              className="bg-slate-800 text-slate-300 border border-slate-700 rounded px-2.5 py-1 outline-none"
            >
              <option value="">All Confidence</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            {(statusFilter || severityFilter || confidenceFilter) && (
              <button
                onClick={() => {
                  setStatusFilter('');
                  setSeverityFilter('');
                  setConfidenceFilter('');
                }}
                className="text-xs text-cyan-400 hover:text-cyan-300 ml-auto"
              >
                Clear Filters
              </button>
            )}
          </div>

          {/* Investigations Table */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Investigation & Title</th>
                  <th className="py-3 px-4">Risk / Severity</th>
                  <th className="py-3 px-4">Evidence Chain</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Triage Status</th>
                  <th className="py-3 px-4">Detected</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {investigations.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-500">
                      <Network className="w-8 h-8 mx-auto mb-2 opacity-40 text-cyan-500" />
                      <p className="text-sm">No exfiltration investigations found.</p>
                      <p className="text-xs text-slate-600 mt-1">
                        Run a correlation pass or trigger a lab scenario to generate events.
                      </p>
                    </td>
                  </tr>
                ) : (
                  investigations.map((inv) => (
                    <tr
                      key={inv.id}
                      onClick={() => handleSelectInvestigation(inv.id)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition ${
                        selectedInvestigationId === inv.id ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-white">{inv.title}</div>
                        <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                          {inv.description}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm text-white">
                            {inv.risk_score}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(inv.severity)}`}>
                            {inv.severity}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                          {inv.evidence_completeness}
                        </span>
                        <span className="text-[11px] text-slate-500 ml-1.5">
                          ({inv.rules_triggered_count} rules)
                        </span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className="text-[11px] font-semibold text-slate-300">
                          {inv.evidence_confidence}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getStatusBadge(inv.status)}`}>
                          {inv.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-[11px]">
                        {new Date(inv.created_at).toLocaleTimeString()} ({new Date(inv.created_at).toLocaleDateString()})
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectInvestigation(inv.id);
                          }}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded text-xs font-medium transition border border-slate-700"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Outbound Transfer Telemetry */}
      {activeTab === 'transfers' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-400 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
            <span>
              Recorded outbound transfer events (synthetic lab telemetry & network collector traces).
            </span>
            <span className="text-amber-400 font-medium">
              Note: Lab fixtures are explicitly tagged as LAB_SIMULATED for audit integrity.
            </span>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Destination Host</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Volume (Bytes)</th>
                  <th className="py-3 px-4">Evidence Provenance</th>
                  <th className="py-3 px-4">Process / Staging</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                {transfers.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-500 font-sans">
                      No transfer telemetry recorded. Trigger a lab scenario from the header menu.
                    </td>
                  </tr>
                ) : (
                  transfers.map((xfer) => (
                    <tr key={xfer.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(xfer.occurred_at).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-4 font-semibold text-white">
                        {xfer.destination_host}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                          {xfer.destination_category}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-cyan-400">{xfer.protocol}</td>
                      <td className="py-3 px-4 text-amber-300 font-bold">
                        {(xfer.byte_count / (1024 * 1024)).toFixed(2)} MB ({xfer.byte_count.toLocaleString()} B)
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-sans font-semibold ${getProvenanceBadge(xfer.evidence_provenance)}`}>
                          {xfer.evidence_provenance}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] font-sans">
                        {xfer.trusted_process_reference || xfer.verified_file_reference || '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Detection Rules Suite */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {rules.map((rule) => (
              <div
                key={rule.rule_id}
                className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between shadow-md"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                      {rule.rule_id}
                    </span>
                    <span className="text-[10px] font-semibold text-slate-400">
                      v{rule.version}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-2">{rule.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    {rule.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">Weight:</span>
                    <span className="font-mono font-bold text-amber-400">+{rule.score_contribution}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">Relationship:</span>
                    <span className={`px-2 py-0.2 rounded text-[10px] font-mono ${getRelationshipBadge(rule.relationship_type)}`}>
                      {rule.relationship_type}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SLIDE-OUT INVESTIGATION & FORENSIC TIMELINE DRAWER */}
      {selectedInvestigationId && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end animate-in fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto flex flex-col shadow-2xl">
            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-950/80 sticky top-0 z-10">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">
                    INVESTIGATION
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${investigationDetail ? getSeverityBadge(investigationDetail.severity) : ''}`}>
                    {investigationDetail?.severity}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${investigationDetail ? getStatusBadge(investigationDetail.status) : ''}`}>
                    {investigationDetail?.status}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white mt-1">
                  {investigationDetail?.title || 'Loading Investigation...'}
                </h2>
              </div>
              <button
                onClick={() => setSelectedInvestigationId(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg bg-slate-800/60"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {drawerLoading ? (
              <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
                <RefreshCw className="w-5 h-5 animate-spin mr-2 text-cyan-400" />
                Loading forensic timeline and evidence...
              </div>
            ) : investigationDetail ? (
              <div className="p-6 space-y-6 flex-1">
                {/* Risk Score & Evidence Meta */}
                <div className="grid grid-cols-3 gap-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                  <div>
                    <div className="text-[11px] text-slate-500 uppercase font-semibold">Risk Score</div>
                    <div className="text-2xl font-bold font-mono text-red-400 mt-0.5">
                      {investigationDetail.risk_score} / 100
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-slate-500 uppercase font-semibold">Confidence</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">
                      {investigationDetail.evidence_confidence}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-slate-500 uppercase font-semibold">Completeness</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">
                      {investigationDetail.evidence_completeness}
                    </div>
                  </div>
                </div>

                {/* Triage Status Transitions */}
                <div className="bg-slate-950/40 p-4 rounded-xl border border-slate-800 space-y-3">
                  <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                    Triage & Incident Workflow
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    {(['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'INCONCLUSIVE'] as InvestigationStatus[]).map(
                      (st) => (
                        <button
                          key={st}
                          onClick={() => handleUpdateStatus(st)}
                          disabled={triageLoading || investigationDetail.status === st}
                          className={`px-2.5 py-1 rounded text-xs font-semibold transition border ${
                            investigationDetail.status === st
                              ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                              : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:text-white'
                          }`}
                        >
                          {st}
                        </button>
                      )
                    )}
                  </div>

                  {/* Analyst Notes Input */}
                  <div className="pt-2">
                    <textarea
                      value={triageNotes}
                      onChange={(e) => setTriageNotes(e.target.value)}
                      placeholder="Add analyst triage findings or forensic notes..."
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:ring-1 focus:ring-cyan-500 outline-none resize-none h-16"
                    />
                    <div className="flex items-center justify-between mt-1.5">
                      <input
                        type="text"
                        value={triageAnalyst}
                        onChange={(e) => setTriageAnalyst(e.target.value)}
                        placeholder="Analyst ID"
                        className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 w-36 outline-none"
                      />
                      <button
                        onClick={() => handleUpdateStatus(investigationDetail.status)}
                        disabled={triageLoading || !triageNotes.trim()}
                        className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium disabled:opacity-50 transition flex items-center gap-1"
                      >
                        <Send className="w-3 h-3" />
                        Log Notes
                      </button>
                    </div>
                  </div>

                  {/* Existing Notes Audit Log */}
                  {investigationDetail.investigation_notes && (
                    <div className="mt-3 p-3 bg-slate-900 border border-slate-800/80 rounded-lg font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                      {investigationDetail.investigation_notes}
                    </div>
                  )}
                </div>

                {/* Forensic Chronological Timeline */}
                <div>
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-cyan-400" />
                    Forensic Chronological Timeline
                  </h3>

                  <div className="relative pl-6 space-y-4 before:content-[''] before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                    {timeline.map((item) => (
                      <div key={item.id} className="relative group">
                        {/* Bullet Icon */}
                        <div className="absolute -left-6 top-1 w-5 h-5 rounded-full bg-slate-950 border border-slate-700 flex items-center justify-center">
                          {item.category === 'FILE_ACTIVITY' && <FileText className="w-3 h-3 text-blue-400" />}
                          {item.category === 'ARCHIVE_EVENT' && <FileArchive className="w-3 h-3 text-purple-400" />}
                          {item.category === 'OUTBOUND_TRANSFER' && <ArrowUpRight className="w-3 h-3 text-amber-400" />}
                          {item.category === 'CORRELATION_RULE' && <ShieldAlert className="w-3 h-3 text-red-400" />}
                        </div>

                        {/* Timeline Item Box */}
                        <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 text-xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-white">{item.title}</span>
                            <span className="text-[10px] text-slate-500 font-mono">
                              {new Date(item.timestamp).toLocaleTimeString()}
                            </span>
                          </div>

                          <p className="text-slate-400 text-[11px] leading-relaxed">
                            {item.description}
                          </p>

                          <div className="flex items-center gap-2 pt-1.5">
                            {/* Provenance Tag */}
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${getProvenanceBadge(item.evidence_provenance)}`}>
                              {item.evidence_provenance}
                            </span>
                            {/* Relationship Tag */}
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono ${getRelationshipBadge(item.relationship_type)}`}>
                              {item.relationship_type}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Linked Correlation Rules */}
                {investigationDetail.correlation_records && investigationDetail.correlation_records.length > 0 && (
                  <div>
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                      Triggered Rules & Score Contribution
                    </h3>
                    <div className="space-y-2">
                      {investigationDetail.correlation_records.map((rec) => (
                        <div
                          key={rec.id}
                          className="p-3 bg-slate-950/50 border border-slate-800 rounded-lg text-xs flex items-center justify-between"
                        >
                          <div>
                            <div className="font-semibold text-white">
                              {rec.rule_id} — {rec.rule_name}
                            </div>
                            <div className="text-[11px] text-slate-400 mt-0.5">{rec.summary}</div>
                          </div>
                          <span className="font-mono font-bold text-amber-400 text-sm">
                            +{rec.score_contribution}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
