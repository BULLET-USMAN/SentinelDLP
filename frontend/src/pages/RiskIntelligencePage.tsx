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
  Layers,
  Info,
  Check,
  HelpCircle,
} from 'lucide-react';
import {
  fetchAlertDetails,
  fetchAlertStatistics,
  fetchDetectionRulesCatalog,
  fetchRiskAssessments,
  fetchRiskStatistics,
  fetchSecurityAlerts,
  updateAlertStatus,
} from '../services/api';
import {
  AlertStatistics,
  AlertStatus,
  DetectionRuleCatalogItem,
  RiskAssessmentItem,
  RiskSeverity,
  RiskStatistics,
  SecurityAlertDetail,
  SecurityAlertItem,
} from '../types/risk';

export const RiskIntelligencePage: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'alerts' | 'assessments' | 'rules'>('alerts');

  // Operational state
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Statistics
  const [riskStats, setRiskStats] = useState<RiskStatistics | null>(null);
  const [alertStats, setAlertStats] = useState<AlertStatistics | null>(null);

  // Alerts data & filters
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [alertPage, setAlertPage] = useState<number>(1);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  // Assessments data & filters
  const [assessments, setAssessments] = useState<RiskAssessmentItem[]>([]);
  const [assessmentSeverityFilter, setAssessmentSeverityFilter] = useState<string>('');

  // Rules catalog
  const [rulesCatalog, setRulesCatalog] = useState<DetectionRuleCatalogItem[]>([]);

  // Selected Alert for Triage Drawer
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetail, setAlertDetail] = useState<SecurityAlertDetail | null>(null);
  const [drawerLoading, setDrawerLoading] = useState<boolean>(false);
  const [triageNotes, setTriageNotes] = useState<string>('');
  const [triageActionLoading, setTriageActionLoading] = useState<boolean>(false);
  const [triageSuccessMsg, setTriageSuccessMsg] = useState<string | null>(null);

  // Load overview metrics
  const loadStatistics = useCallback(async () => {
    try {
      const [rStats, aStats] = await Promise.all([
        fetchRiskStatistics(),
        fetchAlertStatistics(),
      ]);
      setRiskStats(rStats);
      setAlertStats(aStats);
    } catch (err: any) {
      console.error('Failed to load risk statistics:', err);
    }
  }, []);

  // Load alerts
  const loadAlerts = useCallback(async () => {
    try {
      const res = await fetchSecurityAlerts(
        alertPage,
        15,
        statusFilter || undefined,
        severityFilter || undefined,
        undefined,
        undefined
      );
      setAlerts(res.items);
    } catch (err: any) {
      console.error('Failed to load alerts:', err);
      setErrorMessage(err.message || 'Failed to fetch alerts');
    }
  }, [alertPage, statusFilter, severityFilter]);

  // Load assessments
  const loadAssessments = useCallback(async () => {
    try {
      const res = await fetchRiskAssessments(
        1,
        25,
        undefined,
        assessmentSeverityFilter || undefined
      );
      setAssessments(res.items);
    } catch (err: any) {
      console.error('Failed to load assessments:', err);
    }
  }, [assessmentSeverityFilter]);

  // Load rules catalog
  const loadRules = useCallback(async () => {
    try {
      const catalog = await fetchDetectionRulesCatalog();
      setRulesCatalog(catalog);
    } catch (err: any) {
      console.error('Failed to load rules catalog:', err);
    }
  }, []);

  // Full refresh
  const handleRefresh = async () => {
    setRefreshing(true);
    setErrorMessage(null);
    try {
      await Promise.all([loadStatistics(), loadAlerts(), loadAssessments()]);
      if (rulesCatalog.length === 0) {
        await loadRules();
      }
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    handleRefresh();
  }, [loadAlerts, loadAssessments, loadStatistics, loadRules]);

  // Auto-refresh timer (every 10s)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadStatistics();
      if (activeTab === 'alerts') loadAlerts();
      if (activeTab === 'assessments') loadAssessments();
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, activeTab, loadStatistics, loadAlerts, loadAssessments]);

  // Load detail when an alert is selected
  const handleSelectAlert = async (id: string) => {
    setSelectedAlertId(id);
    setDrawerLoading(true);
    setTriageSuccessMsg(null);
    setTriageNotes('');
    try {
      const detail = await fetchAlertDetails(id);
      setAlertDetail(detail);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load alert details');
    } finally {
      setDrawerLoading(false);
    }
  };

  // Perform triage action
  const handleTriageAction = async (newStatus: AlertStatus) => {
    if (!selectedAlertId) return;
    setTriageActionLoading(true);
    setTriageSuccessMsg(null);
    try {
      const updated = await updateAlertStatus(selectedAlertId, newStatus, triageNotes);
      setAlertDetail(updated);
      setTriageSuccessMsg(`Alert successfully transitioned to ${newStatus}`);
      setTriageNotes('');
      // Refresh summaries
      loadAlerts();
      loadStatistics();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update alert status');
    } finally {
      setTriageActionLoading(false);
    }
  };

  const getSeverityBadgeClass = (severity: RiskSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border border-orange-800/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border border-amber-800/80';
      case 'LOW':
      default:
        return 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80';
    }
  };

  const getStatusBadgeClass = (status: AlertStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-red-900/40 text-red-300 border border-red-700/60';
      case 'INVESTIGATING':
        return 'bg-blue-900/40 text-blue-300 border border-blue-700/60';
      case 'ACKNOWLEDGED':
        return 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/60';
      case 'RESOLVED':
        return 'bg-emerald-900/40 text-emerald-300 border border-emerald-700/60';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="h-7 w-7 text-emerald-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Risk Intelligence & Threat Alerts
            </h1>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Phase 5: Rule-based threat scoring, explainable detection findings, and SOC alert lifecycle triage.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              autoRefresh
                ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            Auto-Refresh: {autoRefresh ? '10s' : 'Off'}
          </button>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 bg-red-950/60 border border-red-800/80 rounded-xl text-red-200 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-red-400 hover:text-red-300"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Tiles */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Risk Assessment Distribution Tile */}
        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Sliders className="h-4 w-4 text-emerald-400" />
              Risk Score Distribution
            </span>
            <span className="text-xs text-slate-500">
              Avg Score: {riskStats ? `${riskStats.average_score}/100` : '--'}
            </span>
          </div>
          <div className="grid grid-cols-4 gap-2 text-center">
            <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/40">
              <div className="text-lg font-bold text-emerald-400">{riskStats?.low_count ?? 0}</div>
              <div className="text-[10px] text-emerald-300/70 uppercase tracking-wider mt-0.5">Low (0-29)</div>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/40">
              <div className="text-lg font-bold text-amber-400">{riskStats?.medium_count ?? 0}</div>
              <div className="text-[10px] text-amber-300/70 uppercase tracking-wider mt-0.5">Med (30-59)</div>
            </div>
            <div className="p-2.5 rounded-lg bg-orange-950/30 border border-orange-900/40">
              <div className="text-lg font-bold text-orange-400">{riskStats?.high_count ?? 0}</div>
              <div className="text-[10px] text-orange-300/70 uppercase tracking-wider mt-0.5">High (60-79)</div>
            </div>
            <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-900/40">
              <div className="text-lg font-bold text-red-400">{riskStats?.critical_count ?? 0}</div>
              <div className="text-[10px] text-red-300/70 uppercase tracking-wider mt-0.5">Crit (80-100)</div>
            </div>
          </div>
        </div>

        {/* SOC Alert Triage Lifecycle Tile */}
        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              Security Alerts Triage Status
            </span>
            <span className="text-xs text-slate-500">
              Total Alerts: {alertStats?.total_alerts ?? 0}
            </span>
          </div>
          <div className="grid grid-cols-5 gap-2 text-center">
            <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-900/50">
              <div className="text-lg font-bold text-red-400">{alertStats?.open_count ?? 0}</div>
              <div className="text-[10px] text-red-300/80 uppercase tracking-wider mt-0.5">Open</div>
            </div>
            <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/40">
              <div className="text-lg font-bold text-amber-300">{alertStats?.acknowledged_count ?? 0}</div>
              <div className="text-[10px] text-amber-300/70 uppercase tracking-wider mt-0.5">Ack</div>
            </div>
            <div className="p-2.5 rounded-lg bg-blue-950/30 border border-blue-900/40">
              <div className="text-lg font-bold text-blue-300">{alertStats?.investigating_count ?? 0}</div>
              <div className="text-[10px] text-blue-300/70 uppercase tracking-wider mt-0.5">Investig.</div>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/40">
              <div className="text-lg font-bold text-emerald-300">{alertStats?.resolved_count ?? 0}</div>
              <div className="text-[10px] text-emerald-300/70 uppercase tracking-wider mt-0.5">Resolved</div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/50">
              <div className="text-lg font-bold text-slate-400">{alertStats?.false_positive_count ?? 0}</div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-0.5">FP</div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab('alerts')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
            activeTab === 'alerts'
              ? 'border-emerald-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="h-4 w-4" />
          Security Alerts
          {alertStats && alertStats.open_count > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-red-950 text-red-400 border border-red-800 font-bold">
              {alertStats.open_count}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('assessments')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
            activeTab === 'assessments'
              ? 'border-emerald-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="h-4 w-4" />
          All Risk Assessments
          <span className="text-xs text-slate-500">({riskStats?.total_assessments ?? 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
            activeTab === 'rules'
              ? 'border-emerald-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="h-4 w-4" />
          Detection Rules Catalog
          <span className="text-xs text-slate-500">(8 Active)</span>
        </button>
      </div>

      {/* ============================================================== */}
      {/* VIEW 1: SECURITY ALERTS                                         */}
      {/* ============================================================== */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-400">Filters:</span>
            </div>

            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setAlertPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setAlertPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            {(statusFilter || severityFilter) && (
              <button
                onClick={() => {
                  setStatusFilter('');
                  setSeverityFilter('');
                  setAlertPage(1);
                }}
                className="text-xs text-emerald-400 hover:text-emerald-300 ml-auto"
              >
                Reset Filters
              </button>
            )}
          </div>

          {/* Alerts Table */}
          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Threat Score</th>
                  <th className="py-3 px-4">Alert Title</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Repeats</th>
                  <th className="py-3 px-4">Detected At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      <ShieldCheck className="h-10 w-10 mx-auto mb-2 text-slate-600" />
                      <p className="font-medium text-slate-400">No Security Alerts Found</p>
                      <p className="text-xs text-slate-600 mt-1">
                        Filesystem telemetry indicates baseline behavior within safe parameters.
                      </p>
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => handleSelectAlert(alert.id)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getSeverityBadgeClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-slate-100">{alert.risk_score}</span>
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${
                                alert.risk_score >= 80
                                  ? 'bg-red-500'
                                  : alert.risk_score >= 60
                                  ? 'bg-orange-500'
                                  : alert.risk_score >= 30
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${alert.risk_score}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-200">
                        {alert.title}
                        <div className="text-[11px] text-slate-400 truncate max-w-md mt-0.5">
                          {alert.description}
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getStatusBadgeClass(alert.status)}`}>
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-400">
                        {alert.repeat_count > 1 ? (
                          <span className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 font-semibold text-[10px]">
                            {alert.repeat_count}x
                          </span>
                        ) : (
                          '1'
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                        {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectAlert(alert.id);
                          }}
                          className="px-2.5 py-1 bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-400 border border-emerald-800/80 rounded text-xs font-medium transition-colors"
                        >
                          Triage
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

      {/* ============================================================== */}
      {/* VIEW 2: ALL RISK ASSESSMENTS                                    */}
      {/* ============================================================== */}
      {activeTab === 'assessments' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-400">Filter Severity:</span>
            </div>
            <select
              value={assessmentSeverityFilter}
              onChange={(e) => setAssessmentSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL (80-100)</option>
              <option value="HIGH">HIGH (60-79)</option>
              <option value="MEDIUM">MEDIUM (30-59)</option>
              <option value="LOW">LOW (0-29)</option>
            </select>
            {assessmentSeverityFilter && (
              <button
                onClick={() => setAssessmentSeverityFilter('')}
                className="text-xs text-emerald-400 hover:text-emerald-300 ml-auto"
              >
                Reset Filter
              </button>
            )}
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Completeness</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Explanation</th>
                  <th className="py-3 px-4">Assessed At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {assessments.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      No Risk Assessments recorded yet.
                    </td>
                  </tr>
                ) : (
                  assessments.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/50">
                      <td className="py-3 px-4 font-mono font-bold text-slate-100">
                        {a.risk_score}/100
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getSeverityBadgeClass(a.severity)}`}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px] text-slate-400">
                        {a.assessment_status}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                        {a.evidence_completeness}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                        {a.detection_confidence}
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-md">
                        <div className="font-medium text-slate-200">{a.explanation}</div>
                        {a.rule_matches.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {a.rule_matches.map((m, idx) => (
                              <span key={idx} className="px-1.5 py-0.2 bg-slate-800 text-[10px] font-mono rounded text-slate-400">
                                {m.rule_id} (+{m.score_contribution})
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                        {new Date(a.assessed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* VIEW 3: DETECTION RULES CATALOG                                 */}
      {/* ============================================================== */}
      {activeTab === 'rules' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {rulesCatalog.map((rule) => (
            <div key={rule.rule_id} className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-900/60">
                  {rule.rule_id}
                </span>
                <span className="text-[11px] font-medium text-slate-400">
                  Base Points: <span className="text-white font-mono">{rule.base_points}</span>
                </span>
              </div>
              <h3 className="font-semibold text-slate-100 text-sm">{rule.name}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{rule.description}</p>
              <div className="pt-2 text-[11px] text-slate-500 font-mono border-t border-slate-800/80">
                Window: {rule.window_minutes ? `${rule.window_minutes} minutes` : 'Immediate event'} | Version: {rule.version}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ============================================================== */}
      {/* SLIDE-OUT TRIAGE INVESTIGATION DRAWER                           */}
      {/* ============================================================== */}
      {selectedAlertId && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto shadow-2xl p-6 space-y-6 flex flex-col">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  {alertDetail && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadgeClass(alertDetail.severity)}`}>
                      {alertDetail.severity}
                    </span>
                  )}
                  {alertDetail && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getStatusBadgeClass(alertDetail.status)}`}>
                      {alertDetail.status}
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-white">{alertDetail?.title || 'Security Alert Inspection'}</h2>
              </div>
              <button
                onClick={() => setSelectedAlertId(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {drawerLoading ? (
              <div className="py-20 text-center text-slate-500">
                <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2 text-slate-600" />
                Loading complete audit evidence...
              </div>
            ) : alertDetail ? (
              <div className="space-y-6 flex-1">
                {/* Score & Telemetry Meters */}
                <div className="grid grid-cols-3 gap-3 p-3.5 bg-slate-950/80 rounded-xl border border-slate-800">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 font-medium">Risk Threat Score</div>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-0.5">
                      {alertDetail.risk_score}
                      <span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 font-medium">Completeness</div>
                    <div className="text-xs font-semibold text-slate-200 mt-1.5">
                      {alertDetail.assessment?.evidence_completeness || 'COMPLETE'}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 font-medium">Confidence</div>
                    <div className="text-xs font-semibold text-slate-200 mt-1.5">
                      {alertDetail.assessment?.detection_confidence || 'HIGH'}
                    </div>
                  </div>
                </div>

                {/* Explanation narrative */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Info className="h-3.5 w-3.5 text-emerald-400" />
                    Detection Assessment Explanation
                  </h4>
                  <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800/80 text-xs text-slate-200 leading-relaxed">
                    {alertDetail.assessment?.explanation || alertDetail.description}
                  </div>
                </div>

                {/* Technical Boundaries Disclaimer */}
                <div className="p-3 bg-blue-950/30 border border-blue-900/50 rounded-lg text-xs text-blue-200/90 leading-relaxed flex items-start gap-2">
                  <HelpCircle className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold">Defensive Telemetry Boundary: </span>
                    {alertDetail.assessment?.limitations ||
                      'Filesystem notifications observe local operations; they do NOT confirm process attribution, file reads, or network exfiltration.'}
                  </div>
                </div>

                {/* Granular Triggered Rule Matches */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Layers className="h-3.5 w-3.5 text-emerald-400" />
                    Triggered Detection Rules ({alertDetail.assessment?.rule_matches?.length ?? 0})
                  </h4>
                  <div className="space-y-2">
                    {alertDetail.assessment?.rule_matches?.map((match) => (
                      <div
                        key={match.rule_id}
                        className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-emerald-400">{match.rule_id}</span>
                          <span className="text-[11px] font-mono text-slate-400 font-semibold">
                            +{match.score_contribution} pts
                          </span>
                        </div>
                        <div className="font-medium text-slate-200">{match.rule_name}</div>
                        {match.evidence_data && Object.keys(match.evidence_data).length > 0 && (
                          <div className="p-2 bg-slate-900 rounded font-mono text-[10px] text-slate-400 overflow-x-auto">
                            {JSON.stringify(match.evidence_data, null, 2)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Analyst Next Steps */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    Recommended Next Action
                  </h4>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-xs text-slate-300">
                    {alertDetail.recommended_action || 'Review directory events and verify user authorization.'}
                  </div>
                </div>

                {/* Analyst Triage Controls */}
                <div className="space-y-3 pt-4 border-t border-slate-800">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Analyst Triage Decision
                  </h4>

                  {triageSuccessMsg && (
                    <div className="p-2.5 bg-emerald-950/80 border border-emerald-800 text-emerald-200 text-xs rounded-lg flex items-center gap-1.5">
                      <Check className="h-4 w-4 text-emerald-400" />
                      {triageSuccessMsg}
                    </div>
                  )}

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Analyst Commentary / Resolution Notes (Optional)
                    </label>
                    <textarea
                      value={triageNotes}
                      onChange={(e) => setTriageNotes(e.target.value)}
                      placeholder="Add investigation context, verified ticket number, or false positive reason..."
                      rows={2}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {alertDetail.status === 'OPEN' && (
                      <>
                        <button
                          onClick={() => handleTriageAction('ACKNOWLEDGED')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-amber-950/80 hover:bg-amber-900 border border-amber-800 text-amber-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Acknowledge
                        </button>
                        <button
                          onClick={() => handleTriageAction('INVESTIGATING')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-blue-950/80 hover:bg-blue-900 border border-blue-800 text-blue-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={() => handleTriageAction('RESOLVED')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Resolve
                        </button>
                        <button
                          onClick={() => handleTriageAction('FALSE_POSITIVE')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Mark False Positive
                        </button>
                      </>
                    )}

                    {alertDetail.status === 'ACKNOWLEDGED' && (
                      <>
                        <button
                          onClick={() => handleTriageAction('INVESTIGATING')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-blue-950/80 hover:bg-blue-900 border border-blue-800 text-blue-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={() => handleTriageAction('RESOLVED')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Resolve
                        </button>
                        <button
                          onClick={() => handleTriageAction('FALSE_POSITIVE')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Mark False Positive
                        </button>
                      </>
                    )}

                    {alertDetail.status === 'INVESTIGATING' && (
                      <>
                        <button
                          onClick={() => handleTriageAction('RESOLVED')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Resolve
                        </button>
                        <button
                          onClick={() => handleTriageAction('FALSE_POSITIVE')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Mark False Positive
                        </button>
                        <button
                          onClick={() => handleTriageAction('OPEN')}
                          disabled={triageActionLoading}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          Reopen
                        </button>
                      </>
                    )}

                    {(alertDetail.status === 'RESOLVED' || alertDetail.status === 'FALSE_POSITIVE') && (
                      <button
                        onClick={() => handleTriageAction('OPEN')}
                        disabled={triageActionLoading}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                      >
                        Reopen Alert
                      </button>
                    )}
                  </div>
                </div>

                {/* Immutable Audit Trail */}
                <div className="space-y-2 pt-4 border-t border-slate-800">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <History className="h-3.5 w-3.5 text-emerald-400" />
                    Analyst Audit History ({alertDetail.audit_logs?.length ?? 0})
                  </h4>
                  <div className="space-y-2">
                    {alertDetail.audit_logs?.map((log) => (
                      <div
                        key={log.id}
                        className="p-2.5 bg-slate-950/70 border border-slate-800/80 rounded-lg text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-slate-400">
                          <span className="font-semibold text-slate-200">{log.action}</span>
                          <span className="text-[10px]">
                            {new Date(log.performed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400">
                          {log.previous_status} &rarr; <span className="font-semibold text-slate-300">{log.new_status}</span> by {log.performed_by}
                        </div>
                        {log.analyst_notes && (
                          <div className="text-[11px] text-slate-300 italic bg-slate-900 p-1.5 rounded mt-1">
                            &quot;{log.analyst_notes}&quot;
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
