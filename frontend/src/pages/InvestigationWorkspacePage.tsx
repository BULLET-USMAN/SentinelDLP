import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  RefreshCw,
  Clock,
  ArrowUpRight,
  ShieldAlert,
  Archive,
  Radio,
  Globe,
  FileText,
  User,
  Sparkles,
  Info,
  Bot,
  ThumbsUp,
  ThumbsDown,
} from 'lucide-react';
import {
  fetchExfiltrationInvestigations,
  fetchExfiltrationInvestigationDetail,
  fetchExfiltrationTimeline,
  updateExfiltrationInvestigationStatus,
  analyzeInvestigation,
  fetchInvestigationReports,
  submitReportFeedback,
} from '../services/api';
import {
  ExfiltrationInvestigationItem,
  ExfiltrationTimelineItem,
  InvestigationStatus,
  EvidenceProvenance,
} from '../types/exfiltration';
import {
  AIInvestigationReportResponse,
  AnalystReviewStatus,
} from '../types/ai';

interface InvestigationWorkspacePageProps {
  initialInvestigationId?: string | null;
  onNavigateToTab?: (tab: any, targetId?: string) => void;
}

export const InvestigationWorkspacePage: React.FC<InvestigationWorkspacePageProps> = ({
  initialInvestigationId,
  onNavigateToTab: _onNavigateToTab,
}) => {
  const [investigations, setInvestigations] = useState<ExfiltrationInvestigationItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected Investigation
  const [selectedId, setSelectedId] = useState<string | null>(initialInvestigationId || null);
  const [detail, setDetail] = useState<ExfiltrationInvestigationItem | null>(null);
  const [timeline, setTimeline] = useState<ExfiltrationTimelineItem[]>([]);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);

  // Status Update State
  const [analystName, setAnalystName] = useState<string>('soc_investigator');
  const [caseNotes, setCaseNotes] = useState<string>('');
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);
  const [updateFeedback, setUpdateFeedback] = useState<{ text: string; isError?: boolean } | null>(null);

  // AI Analysis State
  const [aiReport, setAiReport] = useState<AIInvestigationReportResponse | null>(null);
  const [loadingAiReport, setLoadingAiReport] = useState<boolean>(false);
  const [feedbackSubmitting, setFeedbackSubmitting] = useState<boolean>(false);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  // Sync initial ID
  useEffect(() => {
    if (initialInvestigationId) {
      setSelectedId(initialInvestigationId);
    }
  }, [initialInvestigationId]);

  const loadInvestigations = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchExfiltrationInvestigations({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        limit: 50,
      });
      setInvestigations(res || []);
      // If none selected and list not empty, select first
      if (!selectedId && res && res.length > 0) {
        setSelectedId(res[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load exfiltration investigations');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter]);

  useEffect(() => {
    loadInvestigations();
  }, [loadInvestigations]);

  // Load detail & timeline
  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      setTimeline([]);
      return;
    }

    let active = true;
    const fetchFullData = async () => {
      try {
        setLoadingDetail(true);
        setUpdateFeedback(null);
        setFeedbackMsg(null);
        const [detRes, timeRes, aiReports] = await Promise.all([
          fetchExfiltrationInvestigationDetail(selectedId),
          fetchExfiltrationTimeline(selectedId),
          fetchInvestigationReports(selectedId).catch(() => []),
        ]);
        if (active) {
          setDetail(detRes);
          setTimeline(timeRes || []);
          setAnalystName(detRes.assigned_analyst || 'soc_investigator');
          setCaseNotes(detRes.investigation_notes || '');
          setAiReport(aiReports && aiReports.length > 0 ? aiReports[0] : null);
        }
      } catch (err: any) {
        if (active) {
          setUpdateFeedback({ text: err.message || 'Failed to load investigation details', isError: true });
        }
      } finally {
        if (active) setLoadingDetail(false);
      }
    };

    fetchFullData();
    return () => {
      active = false;
    };
  }, [selectedId]);

  const handleGenerateAiReport = async () => {
    if (!selectedId) return;
    try {
      setLoadingAiReport(true);
      setFeedbackMsg(null);
      const report = await analyzeInvestigation(selectedId, undefined, true);
      setAiReport(report);
      setFeedbackMsg('AI security analysis generated successfully.');
    } catch (err: any) {
      setFeedbackMsg(`AI Analysis error: ${err.message || 'Failed to generate report'}`);
    } finally {
      setLoadingAiReport(false);
    }
  };

  const handleFeedback = async (reviewStatus: AnalystReviewStatus) => {
    if (!aiReport) return;
    try {
      setFeedbackSubmitting(true);
      const updated = await submitReportFeedback(aiReport.id, reviewStatus, undefined, analystName);
      setAiReport(updated);
      setFeedbackMsg(`Report marked as ${reviewStatus}.`);
    } catch (err: any) {
      setFeedbackMsg(`Feedback submission failed: ${err.message}`);
    } finally {
      setFeedbackSubmitting(false);
    }
  };

  const handleStatusUpdate = async (newStatus: InvestigationStatus) => {
    if (!selectedId) return;
    try {
      setUpdatingStatus(true);
      setUpdateFeedback(null);
      const updated = await updateExfiltrationInvestigationStatus(
        selectedId,
        newStatus,
        analystName,
        caseNotes
      );
      setDetail(updated);
      setUpdateFeedback({ text: `Case status successfully updated to ${newStatus}` });
      loadInvestigations();
    } catch (err: any) {
      setUpdateFeedback({ text: err.message || 'Failed to update case status', isError: true });
    } finally {
      setUpdatingStatus(false);
    }
  };

  const filteredList = investigations.filter(inv => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      inv.title.toLowerCase().includes(q) ||
      inv.description.toLowerCase().includes(q) ||
      inv.id.toLowerCase().includes(q)
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

  const getProvenanceBadgeClass = (prov: EvidenceProvenance) => {
    switch (prov) {
      case 'OBSERVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'IMPORTED':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'LAB_SIMULATED':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'INFERRED':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getTimelineIcon = (cat: string) => {
    switch (cat) {
      case 'FILE_ACTIVITY':
        return <Radio className="w-4 h-4 text-cyan-400" />;
      case 'ARCHIVE_EVENT':
        return <Archive className="w-4 h-4 text-amber-400" />;
      case 'OUTBOUND_TRANSFER':
        return <Globe className="w-4 h-4 text-purple-400" />;
      case 'RISK_ALERT':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case 'CORRELATION_RULE':
        return <Sparkles className="w-4 h-4 text-pink-400" />;
      default:
        return <FileText className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ArrowUpRight className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Investigation Workspace
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono font-normal">
                  {investigations.length} Cases
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Multi-stage forensic event timeline, correlated exfiltration evidence, and analyst case management.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadInvestigations()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Main Workspace Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Investigation Case List */}
        <div className="lg:col-span-4 space-y-4">
          {/* Filter Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 space-y-2.5 shadow-sm">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Filter cases by title, ID..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-2.5 py-1 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Status</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
                <option value="INCONCLUSIVE">Inconclusive</option>
              </select>
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Severity</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          {/* List Items */}
          <div className="space-y-2 max-h-[720px] overflow-y-auto pr-1">
            {error ? (
              <div className="py-8 text-center text-red-400 bg-slate-900 rounded-xl border border-red-900/50 p-4 text-xs">
                {error}
              </div>
            ) : loading && investigations.length === 0 ? (
              <div className="py-12 text-center text-slate-500 bg-slate-900 rounded-xl border border-slate-800">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
                Loading investigations...
              </div>
            ) : filteredList.length === 0 ? (
              <div className="py-12 text-center text-slate-500 bg-slate-900 rounded-xl border border-slate-800">
                <ShieldAlert className="w-6 h-6 mx-auto mb-2 text-slate-600 opacity-40" />
                No exfiltration cases found.
              </div>
            ) : (
              filteredList.map(inv => {
                const isSelected = selectedId === inv.id;
                return (
                  <div
                    key={inv.id}
                    onClick={() => setSelectedId(inv.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800/90 border-cyan-500/60 shadow-md ring-1 ring-cyan-500/20'
                        : 'bg-slate-900 border-slate-800 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(
                          inv.severity
                        )}`}
                      >
                        {inv.severity}
                      </span>
                      <span className="font-mono text-xs font-semibold text-slate-300">
                        Score: <strong className="text-red-400">{inv.risk_score}</strong>
                      </span>
                    </div>

                    <h4 className="text-sm font-semibold text-slate-100 line-clamp-1 mb-1">
                      {inv.title}
                    </h4>
                    <p className="text-xs text-slate-400 line-clamp-2 mb-2">
                      {inv.description}
                    </p>

                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1.5 border-t border-slate-800/80">
                      <span className="font-mono">{inv.status}</span>
                      <span>
                        {new Date(inv.created_at).toLocaleDateString([], {
                          month: 'short',
                          day: 'numeric',
                        })}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Deep-Dive & Timeline Workspace */}
        <div className="lg:col-span-8 space-y-6">
          {selectedId && detail ? (
            <>
              {/* Case Overview Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadgeClass(
                          detail.severity
                        )}`}
                      >
                        {detail.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800">
                        Confidence: {detail.evidence_confidence}
                      </span>
                      <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800">
                        Status: <strong className="text-cyan-400">{detail.status}</strong>
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white">{detail.title}</h2>
                  </div>

                  <div className="text-right sm:border-l sm:border-slate-800 sm:pl-4">
                    <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Risk Score</span>
                    <span className="font-mono text-2xl font-bold text-red-400">{detail.risk_score}</span>
                    <span className="text-xs text-slate-500"> / 100</span>
                  </div>
                </div>

                {/* Causal Modesty Disclosure */}
                <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-800/40 text-xs text-blue-200/90 flex items-start gap-2.5">
                  <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                  <div className="leading-relaxed">
                    <strong>Defensive Engineering Disclosure:</strong> Events are correlated through temporal proximity
                    ({detail.correlation_window_minutes}m window) and heuristic pattern matching. Correlation does not definitively prove
                    malicious intent or confirmed exfiltration without manual forensic verification.
                  </div>
                </div>

                {/* Case Description */}
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950 p-3.5 rounded-lg border border-slate-800/80">
                  {detail.description}
                </div>

                {/* Triggered Correlation Rules */}
                {detail.correlation_records && detail.correlation_records.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Correlated Rules Triggered ({detail.correlation_records.length})
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                      {detail.correlation_records.map(cr => (
                        <div
                          key={cr.id}
                          className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-200">{cr.rule_name}</span>
                            <span className="font-mono font-bold text-amber-400">+{cr.score_contribution} pts</span>
                          </div>
                          <p className="text-slate-400 text-[11px] leading-tight">{cr.summary}</p>
                          <div className="flex items-center gap-2 pt-1 text-[10px] text-slate-500">
                            <span>Rel: <strong className="text-slate-400">{cr.relationship_type}</strong></span>
                            <span>•</span>
                            <span>Completeness: <strong className="text-slate-400">{cr.evidence_completeness}</strong></span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* AI ANALYSIS SECTION (Phase 9) */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                      <Bot className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        AI Security Investigation Analysis
                        <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          {aiReport ? aiReport.model_id : 'LOCAL AI'}
                        </span>
                      </h3>
                      <p className="text-[11px] text-slate-400">
                        Evidence-grounded qualitative analysis, ATT&CK alignment, and human analyst validation.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={handleGenerateAiReport}
                    disabled={loadingAiReport}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
                  >
                    <Sparkles className={`w-3.5 h-3.5 ${loadingAiReport ? 'animate-spin' : ''}`} />
                    {loadingAiReport ? 'Analyzing Evidence...' : aiReport ? 'Re-Analyze Case' : 'Generate AI Report'}
                  </button>
                </div>

                {feedbackMsg && (
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-emerald-400 font-mono">
                    {feedbackMsg}
                  </div>
                )}

                {loadingAiReport ? (
                  <div className="py-12 text-center text-slate-400 space-y-2">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-emerald-400" />
                    <p className="text-xs">Synthesizing evidence and cross-referencing MITRE ATT&CK techniques...</p>
                  </div>
                ) : !aiReport ? (
                  <div className="py-8 text-center text-slate-500 text-xs space-y-2">
                    <p>No AI investigation report generated for this case yet.</p>
                    <button
                      onClick={handleGenerateAiReport}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
                    >
                      Run Initial AI Analysis
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4 text-xs">
                    {/* A. Executive Summary & Assessment */}
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-900 pb-2">
                        <span className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                          Executive Summary & Assessment
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            Confidence: {aiReport.confidence_assessment}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            Completeness: {aiReport.evidence_completeness}
                          </span>
                        </div>
                      </div>
                      <p className="text-slate-200 leading-relaxed font-medium">{aiReport.executive_summary}</p>
                      <p className="text-slate-400 leading-relaxed pt-1 text-[11px]">{aiReport.assessment}</p>
                    </div>

                    {/* B. Observed Facts */}
                    {aiReport.observed_facts && aiReport.observed_facts.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          Verified Supporting Evidence ({aiReport.observed_facts.length})
                        </span>
                        <div className="space-y-1.5">
                          {aiReport.observed_facts.map((fact, idx) => (
                            <div
                              key={idx}
                              className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start justify-between gap-2 text-xs"
                            >
                              <div className="space-y-0.5">
                                <span className="text-slate-200">{fact.fact}</span>
                                {fact.record_id && (
                                  <div className="text-[10px] text-slate-500 font-mono">
                                    Record ID: {fact.record_id}
                                  </div>
                                )}
                              </div>
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
                                {fact.provenance}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* C. Explanations & Missing Evidence */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider block">
                          Plausible Explanations
                        </span>
                        <ul className="space-y-1 text-slate-400 text-[11px] list-disc list-inside">
                          {aiReport.possible_explanations.map((exp, idx) => (
                            <li key={idx}>{exp}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider block">
                          Missing or Unverified Telemetry
                        </span>
                        <ul className="space-y-1 text-slate-400 text-[11px] list-disc list-inside">
                          {aiReport.missing_evidence.map((miss, idx) => (
                            <li key={idx}>{miss}</li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* D. MITRE ATT&CK Mapping */}
                    {aiReport.mitre_attack_mappings && aiReport.mitre_attack_mappings.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          MITRE ATT&CK Mappings ({aiReport.mitre_attack_mappings.length})
                        </span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {aiReport.mitre_attack_mappings.map((m, idx) => (
                            <div
                              key={idx}
                              className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-mono font-bold text-indigo-400">{m.technique_id}</span>
                                <span className="text-[10px] text-slate-500 font-mono">{m.tactic}</span>
                              </div>
                              <div className="font-semibold text-slate-200">{m.technique_name}</div>
                              <p className="text-[11px] text-slate-400 leading-tight">{m.justification}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* E. Recommended Actions */}
                    {aiReport.recommended_actions && aiReport.recommended_actions.length > 0 && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
                          Defensive Investigation Recommendations
                        </span>
                        <ul className="space-y-1 text-slate-300 text-[11px] list-disc list-inside">
                          {aiReport.recommended_actions.map((act, idx) => (
                            <li key={idx}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* F. Analyst Feedback & Validation Bar */}
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-400">Analyst Review:</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            aiReport.analyst_review_status === 'USEFUL'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : aiReport.analyst_review_status === 'INCORRECT'
                              ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {aiReport.analyst_review_status}
                        </span>
                        {aiReport.reviewed_by && (
                          <span className="text-[10px] text-slate-500">by {aiReport.reviewed_by}</span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleFeedback('USEFUL')}
                          disabled={feedbackSubmitting}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-xs border border-emerald-500/30 transition-colors"
                        >
                          <ThumbsUp className="w-3.5 h-3.5" />
                          Mark Useful
                        </button>
                        <button
                          onClick={() => handleFeedback('INCORRECT')}
                          disabled={feedbackSubmitting}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs border border-red-500/30 transition-colors"
                        >
                          <ThumbsDown className="w-3.5 h-3.5" />
                          Mark Incorrect
                        </button>
                        <button
                          onClick={() => handleFeedback('NEEDS_REVIEW')}
                          disabled={feedbackSubmitting}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
                        >
                          Needs Review
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Forensic Timeline */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    Forensic Multi-Stage Event Timeline ({timeline.length})
                  </h3>
                  <span className="text-xs text-slate-500 font-mono">Synthesized Chronology</span>
                </div>

                {loadingDetail ? (
                  <div className="py-12 text-center text-slate-500">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
                    Synthesizing forensic timeline...
                  </div>
                ) : timeline.length === 0 ? (
                  <div className="py-8 text-center text-slate-500 text-xs">
                    No timeline items linked to this investigation.
                  </div>
                ) : (
                  <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800">
                    {timeline.map((item, idx) => (
                      <div key={item.id || idx} className="relative group">
                        {/* Dot / Icon */}
                        <div className="absolute -left-6 top-1 w-5 h-5 rounded-full bg-slate-950 border border-slate-700 flex items-center justify-center">
                          {getTimelineIcon(item.category)}
                        </div>

                        {/* Content Card */}
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 hover:border-slate-700 transition-colors space-y-1.5 text-xs">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-semibold text-slate-200">{item.title}</span>
                            <span className="font-mono text-[11px] text-slate-500">
                              {new Date(item.timestamp).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                              })}
                            </span>
                          </div>

                          <p className="text-slate-400 leading-relaxed text-[11px]">{item.description}</p>

                          <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-900 text-[10px]">
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                              {item.category}
                            </span>
                            <span
                              className={`px-1.5 py-0.5 rounded border ${getProvenanceBadgeClass(
                                item.evidence_provenance
                              )}`}
                            >
                              {item.evidence_provenance}
                            </span>
                            <span className="text-slate-500">
                              Link: <strong className="text-slate-400">{item.relationship_type}</strong>
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* AI ANALYSIS SECTION (Phase 9) */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                      <Bot className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        AI Security Investigation Analysis
                        <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          {aiReport ? aiReport.model_id : 'LOCAL AI'}
                        </span>
                      </h3>
                      <p className="text-[11px] text-slate-400">
                        Evidence-grounded qualitative analysis, ATT&CK alignment, and human analyst validation.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={handleGenerateAiReport}
                    disabled={loadingAiReport}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
                  >
                    <Sparkles className={`w-3.5 h-3.5 ${loadingAiReport ? 'animate-spin' : ''}`} />
                    {loadingAiReport ? 'Analyzing Evidence...' : aiReport ? 'Re-Analyze Case' : 'Generate AI Report'}
                  </button>
                </div>

                {feedbackMsg && (
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-emerald-400 font-mono">
                    {feedbackMsg}
                  </div>
                )}

                {loadingAiReport ? (
                  <div className="py-12 text-center text-slate-400 space-y-2">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-emerald-400" />
                    <p className="text-xs">Synthesizing evidence and cross-referencing MITRE ATT&CK techniques...</p>
                  </div>
                ) : !aiReport ? (
                  <div className="py-8 text-center text-slate-500 text-xs space-y-2">
                    <p>No AI investigation report generated for this case yet.</p>
                    <button
                      onClick={handleGenerateAiReport}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
                    >
                      Run Initial AI Analysis
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4 text-xs">
                    {/* A. Executive Summary & Assessment */}
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-900 pb-2">
                        <span className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                          Executive Summary & Assessment
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            Confidence: {aiReport.confidence_assessment}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            Completeness: {aiReport.evidence_completeness}
                          </span>
                        </div>
                      </div>
                      <p className="text-slate-200 leading-relaxed font-medium">{aiReport.executive_summary}</p>
                      <p className="text-slate-400 leading-relaxed pt-1 text-[11px]">{aiReport.assessment}</p>
                    </div>

                    {/* B. Observed Facts */}
                    {aiReport.observed_facts && aiReport.observed_facts.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          Verified Supporting Evidence ({aiReport.observed_facts.length})
                        </span>
                        <div className="space-y-1.5">
                          {aiReport.observed_facts.map((fact, idx) => (
                            <div
                              key={idx}
                              className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start justify-between gap-2 text-xs"
                            >
                              <div className="space-y-0.5">
                                <span className="text-slate-200">{fact.fact}</span>
                                {fact.record_id && (
                                  <div className="text-[10px] text-slate-500 font-mono">
                                    Record ID: {fact.record_id}
                                  </div>
                                )}
                              </div>
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
                                {fact.provenance}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* C. Explanations & Missing Evidence */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider block">
                          Plausible Explanations
                        </span>
                        <ul className="space-y-1 text-slate-400 text-[11px] list-disc list-inside">
                          {aiReport.possible_explanations.map((exp, idx) => (
                            <li key={idx}>{exp}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider block">
                          Missing or Unverified Telemetry
                        </span>
                        <ul className="space-y-1 text-slate-400 text-[11px] list-disc list-inside">
                          {aiReport.missing_evidence.map((miss, idx) => (
                            <li key={idx}>{miss}</li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* D. MITRE ATT&CK Mapping */}
                    {aiReport.mitre_attack_mappings && aiReport.mitre_attack_mappings.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          MITRE ATT&CK Mappings ({aiReport.mitre_attack_mappings.length})
                        </span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {aiReport.mitre_attack_mappings.map((m, idx) => (
                            <div
                              key={idx}
                              className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-mono font-bold text-indigo-400">{m.technique_id}</span>
                                <span className="text-[10px] text-slate-500 font-mono">{m.tactic}</span>
                              </div>
                              <div className="font-semibold text-slate-200">{m.technique_name}</div>
                              <p className="text-[11px] text-slate-400 leading-tight">{m.justification}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* E. Recommended Actions */}
                    {aiReport.recommended_actions && aiReport.recommended_actions.length > 0 && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
                          Defensive Investigation Recommendations
                        </span>
                        <ul className="space-y-1 text-slate-300 text-[11px] list-disc list-inside">
                          {aiReport.recommended_actions.map((act, idx) => (
                            <li key={idx}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* F. Analyst Feedback & Validation Bar */}
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-400">Analyst Review:</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            aiReport.analyst_review_status === 'USEFUL'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : aiReport.analyst_review_status === 'INCORRECT'
                              ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {aiReport.analyst_review_status}
                        </span>
                        {aiReport.reviewed_by && (
                          <span className="text-[10px] text-slate-500">by {aiReport.reviewed_by}</span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleFeedback('USEFUL')}
                          disabled={feedbackSubmitting}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-xs border border-emerald-500/30 transition-colors"
                        >
                          <ThumbsUp className="w-3.5 h-3.5" />
                          Mark Useful
                        </button>
                        <button
                          onClick={() => handleFeedback('INCORRECT')}
                          disabled={feedbackSubmitting}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs border border-red-500/30 transition-colors"
                        >
                          <ThumbsDown className="w-3.5 h-3.5" />
                          Mark Incorrect
                        </button>
                        <button
                          onClick={() => handleFeedback('NEEDS_REVIEW')}
                          disabled={feedbackSubmitting}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
                        >
                          Needs Review
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Status Update & Case Notes Form */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <User className="w-4 h-4 text-cyan-400" />
                  Investigator Case Management
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">Assigned Investigator</label>
                    <input
                      type="text"
                      value={analystName}
                      onChange={e => setAnalystName(e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Current State</label>
                    <div className="font-mono text-sm text-cyan-400 pt-1 font-semibold">{detail.status}</div>
                  </div>
                </div>

                <div className="text-xs space-y-1">
                  <label className="text-slate-400 block">Investigator Case Notes / Findings</label>
                  <textarea
                    rows={3}
                    value={caseNotes}
                    onChange={e => setCaseNotes(e.target.value)}
                    placeholder="Document forensic assessment, interview findings, root cause, or closure rationale..."
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                {updateFeedback && (
                  <div
                    className={`text-xs p-2.5 rounded-lg border ${
                      updateFeedback.isError
                        ? 'bg-red-950/60 text-red-300 border-red-800'
                        : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                    }`}
                  >
                    {updateFeedback.text}
                  </div>
                )}

                {/* Status action buttons */}
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800">
                  <button
                    onClick={() => handleStatusUpdate('INVESTIGATING')}
                    disabled={updatingStatus || detail.status === 'INVESTIGATING'}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-medium disabled:opacity-40 transition-colors"
                  >
                    Set In Progress
                  </button>
                  <button
                    onClick={() => handleStatusUpdate('RESOLVED')}
                    disabled={updatingStatus || detail.status === 'RESOLVED'}
                    className="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-medium disabled:opacity-40 transition-colors"
                  >
                    Mark Confirmed & Resolved
                  </button>
                  <button
                    onClick={() => handleStatusUpdate('FALSE_POSITIVE')}
                    disabled={updatingStatus || detail.status === 'FALSE_POSITIVE'}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-medium disabled:opacity-40 transition-colors"
                  >
                    Mark False Positive
                  </button>
                  <button
                    onClick={() => handleStatusUpdate('INCONCLUSIVE')}
                    disabled={updatingStatus || detail.status === 'INCONCLUSIVE'}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 text-xs font-medium disabled:opacity-40 transition-colors"
                  >
                    Mark Inconclusive
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-500">
              <Search className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-50" />
              Select an investigation case on the left to inspect its multi-stage forensic timeline.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
export default InvestigationWorkspacePage;