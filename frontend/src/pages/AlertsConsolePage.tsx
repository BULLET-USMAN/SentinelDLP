import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Filter,
  RefreshCw,
  Search,
  User,
  History,
  AlertOctagon,
  X,
  ArrowRight,
} from 'lucide-react';
import {
  fetchSecurityAlerts,
  fetchAlertDetails,
  updateAlertStatus,
} from '../services/api';
import {
  SecurityAlertItem,
  SecurityAlertDetail,
  AlertStatus,
} from '../types/risk';

interface AlertsConsolePageProps {
  initialAlertId?: string | null;
  onNavigateToTab?: (tab: any, targetId?: string) => void;
}

export const AlertsConsolePage: React.FC<AlertsConsolePageProps> = ({
  initialAlertId,
  onNavigateToTab: _onNavigateToTab,
}) => {
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Pagination
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);
  const pageSize = 15;

  // Drawer / Inspection
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(initialAlertId || null);
  const [alertDetail, setAlertDetail] = useState<SecurityAlertDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [triageNotes, setTriageNotes] = useState<string>('');
  const [analystName, setAnalystName] = useState<string>('soc_analyst');
  const [triageSubmitting, setTriageSubmitting] = useState<boolean>(false);
  const [triageMessage, setTriageMessage] = useState<{ text: string; isError?: boolean } | null>(null);

  // Sync initialAlertId when prop changes
  useEffect(() => {
    if (initialAlertId) {
      setSelectedAlertId(initialAlertId);
    }
  }, [initialAlertId]);

  const loadAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchSecurityAlerts(
        page,
        pageSize,
        statusFilter === 'ALL' ? undefined : statusFilter,
        severityFilter === 'ALL' ? undefined : severityFilter,
      );
      setAlerts(res.items || []);
      setTotalCount(res.total || 0);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve security alerts from API');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, severityFilter]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  // Load detail when an alert is selected
  useEffect(() => {
    if (!selectedAlertId) {
      setAlertDetail(null);
      return;
    }

    let active = true;
    const loadDetail = async () => {
      try {
        setLoadingDetail(true);
        setTriageMessage(null);
        const detail = await fetchAlertDetails(selectedAlertId);
        if (active) {
          setAlertDetail(detail);
          setTriageNotes(detail.resolution_notes || '');
        }
      } catch (err: any) {
        if (active) {
          setTriageMessage({ text: err.message || 'Failed to load alert details', isError: true });
        }
      } finally {
        if (active) setLoadingDetail(false);
      }
    };

    loadDetail();
    return () => {
      active = false;
    };
  }, [selectedAlertId]);

  const handleUpdateStatus = async (newStatus: AlertStatus) => {
    if (!selectedAlertId) return;
    try {
      setTriageSubmitting(true);
      setTriageMessage(null);
      const updated = await updateAlertStatus(
        selectedAlertId,
        newStatus,
        triageNotes,
        analystName
      );
      setAlertDetail(updated);
      setTriageMessage({ text: `Alert successfully updated to ${newStatus}` });
      // Refresh list to update status badge in table
      loadAlerts();
    } catch (err: any) {
      setTriageMessage({ text: err.message || 'Failed to update alert status', isError: true });
    } finally {
      setTriageSubmitting(false);
    }
  };

  // Filter client-side by search query
  const filteredAlerts = alerts.filter(a => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.title?.toLowerCase().includes(q) ||
      a.description?.toLowerCase().includes(q) ||
      a.deduplication_key?.toLowerCase().includes(q) ||
      a.id.toLowerCase().includes(q)
    );
  });

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-800/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadgeClass = (st: string) => {
    switch (st) {
      case 'OPEN':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'ACKNOWLEDGED':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'INVESTIGATING':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
      case 'RESOLVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'FALSE_POSITIVE':
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Security Alerts Console
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono font-normal">
                  {totalCount} Total
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Centralized triage, risk score explanations, status management, and immutable audit logs.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadAlerts()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[280px]">
          {/* Search Box */}
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search alert title, deduplication key, ID..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-xs text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={e => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-red-500/50"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={e => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-red-500/50"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {/* Page / Count Info */}
        <div className="text-xs text-slate-500 font-mono">
          Showing {filteredAlerts.length} of {totalCount} alerts
        </div>
      </div>

      {/* Main Table / Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Alerts Table */}
        <div className={`${selectedAlertId ? 'lg:col-span-7' : 'lg:col-span-12'} transition-all`}>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800 font-semibold tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Severity / Score</th>
                    <th className="py-3 px-4">Alert Details</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Repeat</th>
                    <th className="py-3 px-4">Created</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {loading && alerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-slate-500">
                        <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-slate-400" />
                        Loading security alerts...
                      </td>
                    </tr>
                  ) : error ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-red-400">
                        <AlertOctagon className="w-6 h-6 mx-auto mb-1 text-red-500" />
                        {error}
                      </td>
                    </tr>
                  ) : filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-slate-500">
                        <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-40" />
                        No security alerts matching the selected criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map(alert => {
                      const isSelected = selectedAlertId === alert.id;
                      return (
                        <tr
                          key={alert.id}
                          onClick={() => setSelectedAlertId(alert.id)}
                          className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                            isSelected ? 'bg-slate-800/70 border-l-4 border-l-red-500' : ''
                          }`}
                        >
                          {/* Severity & Score */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadgeClass(
                                  alert.severity
                                )}`}
                              >
                                {alert.severity}
                              </span>
                              <span className="font-mono text-xs font-semibold text-slate-200">
                                {alert.risk_score}/100
                              </span>
                            </div>
                          </td>

                          {/* Details */}
                          <td className="py-3 px-4 min-w-[200px] max-w-[320px]">
                            <div className="font-medium text-slate-200 truncate">{alert.title}</div>
                            <div className="text-xs text-slate-500 truncate mt-0.5">
                              {alert.description || alert.deduplication_key}
                            </div>
                          </td>

                          {/* Status */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            <span
                              className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium border ${getStatusBadgeClass(
                                alert.status
                              )}`}
                            >
                              {alert.status}
                            </span>
                          </td>

                          {/* Repeat count */}
                          <td className="py-3 px-4 whitespace-nowrap font-mono text-xs text-slate-400">
                            {alert.repeat_count > 1 ? (
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-amber-400 font-semibold">
                                x{alert.repeat_count}
                              </span>
                            ) : (
                              '1'
                            )}
                          </td>

                          {/* Timestamp */}
                          <td className="py-3 px-4 whitespace-nowrap text-xs text-slate-400 font-mono">
                            {new Date(alert.created_at).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                              month: 'short',
                              day: 'numeric',
                            })}
                          </td>

                          {/* Action */}
                          <td className="py-3 px-4 whitespace-nowrap text-right">
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                setSelectedAlertId(alert.id);
                              }}
                              className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                                isSelected
                                  ? 'bg-red-500/20 text-red-400'
                                  : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                              }`}
                            >
                              Triage
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalCount > pageSize && (
              <div className="border-t border-slate-800 px-4 py-3 flex items-center justify-between bg-slate-950">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span className="text-xs text-slate-400 font-mono">
                  Page {page} of {Math.ceil(totalCount / pageSize)}
                </span>
                <button
                  disabled={page >= Math.ceil(totalCount / pageSize)}
                  onClick={() => setPage(p => p + 1)}
                  className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Slide-out / Right-side Inspection Drawer */}
        {selectedAlertId && (
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-6 shadow-md sticky top-6">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">
                  Alert Inspection & Triage
                </span>
                <h3 className="text-lg font-bold text-white mt-1 break-words">
                  {alertDetail?.title || 'Loading Alert...'}
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlertId(null)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {loadingDetail ? (
              <div className="py-12 text-center text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-slate-400" />
                Loading alert telemetry & audit logs...
              </div>
            ) : alertDetail ? (
              <div className="space-y-6 text-sm">
                {/* Meta details */}
                <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                  <div>
                    <span className="text-xs text-slate-500">Severity</span>
                    <div className="mt-0.5">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadgeClass(
                          alertDetail.severity
                        )}`}
                      >
                        {alertDetail.severity}
                      </span>
                    </div>
                  </div>
                  <div>
                    <span className="text-xs text-slate-500">Calculated Score</span>
                    <div className="font-mono text-base font-bold text-red-400">
                      {alertDetail.risk_score} <span className="text-xs text-slate-500">/ 100</span>
                    </div>
                  </div>
                  <div>
                    <span className="text-xs text-slate-500">Status</span>
                    <div className="mt-0.5">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold border ${getStatusBadgeClass(
                          alertDetail.status
                        )}`}
                      >
                        {alertDetail.status}
                      </span>
                    </div>
                  </div>
                  <div>
                    <span className="text-xs text-slate-500">Root Directory</span>
                    <div className="font-mono text-xs text-slate-300 truncate mt-0.5">
                      {alertDetail.root_id || 'synthetic_samples'}
                    </div>
                  </div>
                </div>

                {/* Score Explanation & Rule Matches */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    Detection Explanation & Rules
                  </h4>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
                    <p className="leading-relaxed">
                      {alertDetail.assessment?.explanation || alertDetail.description}
                    </p>
                    {alertDetail.recommended_action && (
                      <div className="pt-2 border-t border-slate-800/80 text-amber-300/90 flex items-start gap-1.5">
                        <span className="font-semibold shrink-0">Recommendation:</span>
                        <span>{alertDetail.recommended_action}</span>
                      </div>
                    )}
                  </div>

                  {/* Matched Rules */}
                  {alertDetail.assessment?.rule_matches && alertDetail.assessment.rule_matches.length > 0 && (
                    <div className="mt-3 space-y-2">
                      <div className="text-[11px] font-semibold text-slate-400">Triggered Rules:</div>
                      {alertDetail.assessment.rule_matches.map((rm, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs"
                        >
                          <div>
                            <span className="font-semibold text-slate-200">{rm.rule_name}</span>
                            <span className="text-slate-500 ml-1.5 font-mono text-[10px]">
                              v{rm.rule_version}
                            </span>
                          </div>
                          <span className="font-mono font-semibold text-amber-400">
                            +{rm.score_contribution} pts
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Triage & Status Transition Form */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    Analyst Triage Action
                  </h4>

                  <div className="space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className="text-[11px] text-slate-500 block mb-1">Analyst Identity</label>
                        <input
                          type="text"
                          value={analystName}
                          onChange={e => setAnalystName(e.target.value)}
                          className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] text-slate-500 block mb-1">Quick Action</label>
                        <div className="text-xs text-slate-400 pt-1.5">Choose target status below</div>
                      </div>
                    </div>

                    <div>
                      <label className="text-[11px] text-slate-500 block mb-1">Triage / Resolution Notes</label>
                      <textarea
                        rows={2}
                        value={triageNotes}
                        onChange={e => setTriageNotes(e.target.value)}
                        placeholder="Document investigation findings, containment steps or false positive rationale..."
                        className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    {triageMessage && (
                      <div
                        className={`text-xs p-2 rounded border ${
                          triageMessage.isError
                            ? 'bg-red-950/60 text-red-300 border-red-800'
                            : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                        }`}
                      >
                        {triageMessage.text}
                      </div>
                    )}

                    {/* Transition Buttons */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                      <button
                        onClick={() => handleUpdateStatus('ACKNOWLEDGED')}
                        disabled={triageSubmitting || alertDetail.status === 'ACKNOWLEDGED'}
                        className="px-2 py-1.5 rounded bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium disabled:opacity-40 transition-colors"
                      >
                        Acknowledge
                      </button>
                      <button
                        onClick={() => handleUpdateStatus('INVESTIGATING')}
                        disabled={triageSubmitting || alertDetail.status === 'INVESTIGATING'}
                        className="px-2 py-1.5 rounded bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-medium disabled:opacity-40 transition-colors"
                      >
                        Investigate
                      </button>
                      <button
                        onClick={() => handleUpdateStatus('RESOLVED')}
                        disabled={triageSubmitting || alertDetail.status === 'RESOLVED'}
                        className="px-2 py-1.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-medium disabled:opacity-40 transition-colors"
                      >
                        Resolve
                      </button>
                      <button
                        onClick={() => handleUpdateStatus('FALSE_POSITIVE')}
                        disabled={triageSubmitting || alertDetail.status === 'FALSE_POSITIVE'}
                        className="px-2 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-medium disabled:opacity-40 transition-colors"
                      >
                        False Positive
                      </button>
                    </div>
                  </div>
                </div>

                {/* Immutable Audit Log */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-slate-400" />
                    Immutable Audit Trail ({alertDetail.audit_logs?.length || 0})
                  </h4>
                  {alertDetail.audit_logs && alertDetail.audit_logs.length > 0 ? (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {alertDetail.audit_logs.map(log => (
                        <div
                          key={log.id}
                          className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between text-slate-400">
                            <span className="font-semibold text-slate-300 flex items-center gap-1">
                              <span>{log.previous_status}</span>
                              <ArrowRight className="w-3 h-3 text-slate-500" />
                              <span className="text-cyan-400">{log.new_status}</span>
                            </span>
                            <span className="font-mono text-[10px]">
                              {new Date(log.performed_at).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                              })}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-slate-500 text-[11px]">
                            <span>By: <strong className="text-slate-400 font-normal">{log.performed_by}</strong></span>
                            {log.analyst_notes && (
                              <>
                                <span>•</span>
                                <span className="italic text-slate-400 truncate">"{log.analyst_notes}"</span>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded bg-slate-950 border border-slate-800/60 text-xs text-slate-500 text-center">
                      No status transitions recorded yet. Initial alert state is OPEN.
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
};
export default AlertsConsolePage;