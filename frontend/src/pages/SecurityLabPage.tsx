import React, { useState, useEffect } from 'react';
import {
  FlaskConical,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileText,
  Clock,
  Crosshair,
  Percent,
  Check,
  Copy,
  Download,
} from 'lucide-react';
import {
  fetchSimulationScenarios,
  fetchSimulationRuns,
  triggerSimulationRun,
  fetchSimulationMetrics,
  fetchSubsystemCoverage,
  fetchSimulationReport,
} from '../services/api';
import {
  ScenarioDefinition,
  SimulationRunResponse,
  GlobalDetectionMetrics,
  SubsystemCoverageItem,
  SimulationReportResponse,
} from '../types/simulation';

export const SecurityLabPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [metrics, setMetrics] = useState<GlobalDetectionMetrics | null>(null);
  const [coverage, setCoverage] = useState<SubsystemCoverageItem[]>([]);
  const [runs, setRuns] = useState<SimulationRunResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Active Execution State
  const [activeRun, setActiveRun] = useState<SimulationRunResponse | null>(null);
  const [executingScenarioId, setExecutingScenarioId] = useState<string | null>(null);
  const [customSeed, setCustomSeed] = useState<number>(42);
  const [autoCleanup, setAutoCleanup] = useState<boolean>(true);

  // Report Modal State
  const [selectedReport, setSelectedReport] = useState<SimulationReportResponse | null>(null);
  const [loadingReport, setLoadingReport] = useState<boolean>(false);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // Active Tab: Scenarios, Coverage Matrix, Run History
  const [activeTab, setActiveTab] = useState<'scenarios' | 'coverage' | 'history'>('scenarios');

  useEffect(() => {
    loadLabData();
  }, []);

  const loadLabData = async () => {
    try {
      setLoading(true);
      const [scenData, metricData, covData, runData] = await Promise.all([
        fetchSimulationScenarios(),
        fetchSimulationMetrics(),
        fetchSubsystemCoverage(),
        fetchSimulationRuns(20),
      ]);
      setScenarios(scenData);
      setMetrics(metricData);
      setCoverage(covData);
      setRuns(runData);

      if (runData.length > 0 && !activeRun) {
        setActiveRun(runData[0]);
      }
    } catch (err) {
      console.error('Error loading simulation lab data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchScenario = async (scenarioId: string) => {
    try {
      setExecutingScenarioId(scenarioId);
      const response = await triggerSimulationRun({
        scenario_id: scenarioId,
        custom_seed: customSeed,
        auto_cleanup: autoCleanup,
      });
      setActiveRun(response);
      // Refresh historical runs and metrics
      const [updatedRuns, updatedMetrics] = await Promise.all([
        fetchSimulationRuns(20),
        fetchSimulationMetrics(),
      ]);
      setRuns(updatedRuns);
      setMetrics(updatedMetrics);
    } catch (err) {
      console.error('Failed to run simulation:', err);
      alert(err instanceof Error ? err.message : 'Simulation run failed.');
    } finally {
      setExecutingScenarioId(null);
    }
  };

  const handleViewReport = async (runId: string) => {
    try {
      setLoadingReport(true);
      const report = await fetchSimulationReport(runId);
      setSelectedReport(report);
      setCopiedReport(false);
    } catch (err) {
      console.error('Failed to load report:', err);
      alert('Report could not be retrieved.');
    } finally {
      setLoadingReport(false);
    }
  };

  const handleCopyReport = () => {
    if (selectedReport) {
      navigator.clipboard.writeText(selectedReport.markdown_content);
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    }
  };

  const handleDownloadReport = () => {
    if (selectedReport) {
      const blob = new Blob([selectedReport.markdown_content], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `simulation_report_${selectedReport.run_id.slice(0, 8)}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const filteredScenarios = scenarios.filter((s) => {
    if (categoryFilter === 'ALL') return true;
    if (categoryFilter === 'BENIGN') return s.negative_control;
    return s.category === categoryFilter;
  });

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between bg-gray-900 border border-gray-800 rounded-xl p-6 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
              <FlaskConical className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Cyberattack Simulation & Testing Lab
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  Phase 10 Laboratory
                </span>
              </h1>
              <p className="text-sm text-gray-400 mt-1">
                Validate SentinelDLP's detection fidelity, false-positive resistance, and accuracy metrics in a secure sandbox.
              </p>
            </div>
          </div>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 bg-gray-800/60 px-3 py-1.5 rounded-lg border border-gray-700/50 text-xs">
            <span className="text-gray-400">Seed:</span>
            <input
              type="number"
              value={customSeed}
              onChange={(e) => setCustomSeed(parseInt(e.target.value) || 42)}
              className="w-14 bg-gray-900 border border-gray-700 rounded px-1.5 py-0.5 text-center text-gray-200 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer bg-gray-800/60 px-3 py-1.5 rounded-lg border border-gray-700/50">
            <input
              type="checkbox"
              checked={autoCleanup}
              onChange={(e) => setAutoCleanup(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-emerald-500 focus:ring-0"
            />
            Auto-Purge Sandbox
          </label>

          <button
            onClick={loadLabData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-medium border border-gray-700 transition"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Lab
          </button>
        </div>
      </div>

      {/* Global Accuracy Metrics & Confusion Matrix */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-gray-400 font-medium">Total Runs</div>
            <div className="text-xl font-bold text-white mt-1">{metrics.total_runs}</div>
            <div className="text-[10px] text-gray-500 mt-0.5">{metrics.passed_runs} passed</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-emerald-400 font-medium flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> True Pos (TP)
            </div>
            <div className="text-xl font-bold text-emerald-400 mt-1">{metrics.true_positives}</div>
            <div className="text-[10px] text-gray-500 mt-0.5">Correct attacks</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-amber-400 font-medium flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" /> False Pos (FP)
            </div>
            <div className="text-xl font-bold text-amber-400 mt-1">{metrics.false_positives}</div>
            <div className="text-[10px] text-gray-500 mt-0.5">Benign flagged</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-blue-400 font-medium flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> True Neg (TN)
            </div>
            <div className="text-xl font-bold text-blue-400 mt-1">{metrics.true_negatives}</div>
            <div className="text-[10px] text-gray-500 mt-0.5">Benign cleared</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-rose-400 font-medium flex items-center gap-1">
              <XCircle className="w-3.5 h-3.5" /> False Neg (FN)
            </div>
            <div className="text-xl font-bold text-rose-400 mt-1">{metrics.false_negatives}</div>
            <div className="text-[10px] text-gray-500 mt-0.5">Missed attacks</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-indigo-400 font-medium flex items-center gap-1">
              <Crosshair className="w-3.5 h-3.5" /> Precision
            </div>
            <div className="text-xl font-bold text-indigo-300 mt-1">
              {(metrics.overall_precision * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-gray-500 mt-0.5">TP / (TP + FP)</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-cyan-400 font-medium flex items-center gap-1">
              <Percent className="w-3.5 h-3.5" /> Recall
            </div>
            <div className="text-xl font-bold text-cyan-300 mt-1">
              {(metrics.overall_recall * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-gray-500 mt-0.5">TP / (TP + FN)</div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-3.5">
            <div className="text-xs text-purple-400 font-medium flex items-center gap-1">
              <Percent className="w-3.5 h-3.5" /> F1 Score
            </div>
            <div className="text-xl font-bold text-purple-300 mt-1">
              {(metrics.overall_f1 * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-gray-500 mt-0.5">Harmonic Mean</div>
          </div>
        </div>
      )}

      {/* Main Tab Navigation */}
      <div className="flex border-b border-gray-800 gap-6 text-sm">
        <button
          onClick={() => setActiveTab('scenarios')}
          className={`pb-3 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'scenarios'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <FlaskConical className="w-4 h-4" />
          Validation Scenarios ({scenarios.length})
        </button>

        <button
          onClick={() => setActiveTab('coverage')}
          className={`pb-3 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'coverage'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Crosshair className="w-4 h-4" />
          Subsystem Coverage Matrix
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`pb-3 font-medium transition flex items-center gap-2 border-b-2 ${
            activeTab === 'history'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          <Clock className="w-4 h-4" />
          Execution History ({runs.length})
        </button>
      </div>

      {/* TAB 1: Scenario Library + Active Execution Split */}
      {activeTab === 'scenarios' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Scenario Catalog (7 cols) */}
          <div className="lg:col-span-7 space-y-4">
            {/* Filter Chips */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
              {[
                { id: 'ALL', label: 'All Scenarios' },
                { id: 'BENIGN', label: 'Benign Baseline' },
                { id: 'DATA_DISCOVERY', label: 'Data Discovery' },
                { id: 'RAPID_MODIFICATION', label: 'Rapid Modifications' },
                { id: 'BULK_RENAME', label: 'Bulk Renaming' },
                { id: 'STAGING_ARCHIVE', label: 'Archive Staging' },
                { id: 'DATA_EXFILTRATION', label: 'Data Exfiltration' },
                { id: 'NETWORK_ANOMALY', label: 'Network Telemetry' },
                { id: 'AI_VALIDATION', label: 'AI Analyst Validation' },
              ].map((filter) => (
                <button
                  key={filter.id}
                  onClick={() => setCategoryFilter(filter.id)}
                  className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition font-medium border ${
                    categoryFilter === filter.id
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'bg-gray-900 text-gray-400 border-gray-800 hover:bg-gray-800'
                  }`}
                >
                  {filter.label}
                </button>
              ))}
            </div>

            {/* Scenario Cards */}
            <div className="space-y-3">
              {filteredScenarios.map((scen) => (
                <div
                  key={scen.scenario_id}
                  className="bg-gray-900 border border-gray-800 hover:border-gray-700 transition rounded-xl p-5"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs px-2 py-0.5 rounded font-bold bg-gray-800 text-gray-200 border border-gray-700">
                          {scen.scenario_id}
                        </span>
                        <h3 className="font-semibold text-white text-base">{scen.name}</h3>
                        {scen.negative_control && (
                          <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider bg-blue-500/10 text-blue-400 border border-blue-500/30">
                            Negative Control
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">{scen.description}</p>
                    </div>

                    <button
                      onClick={() => handleLaunchScenario(scen.scenario_id)}
                      disabled={executingScenarioId === scen.scenario_id}
                      className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-800 text-white rounded-lg text-xs font-semibold shadow-sm transition whitespace-nowrap"
                    >
                      <Play
                        className={`w-3.5 h-3.5 ${
                          executingScenarioId === scen.scenario_id ? 'animate-spin' : ''
                        }`}
                      />
                      {executingScenarioId === scen.scenario_id ? 'Running...' : 'Execute'}
                    </button>
                  </div>

                  {/* Metadata Footer */}
                  <div className="mt-4 pt-3 border-t border-gray-800/80 flex flex-wrap items-center justify-between text-xs gap-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-gray-500">Subsystems:</span>
                      {scen.target_subsystems.map((sub) => (
                        <span
                          key={sub}
                          className="px-2 py-0.5 bg-gray-800/80 text-gray-300 rounded text-[10px] font-mono border border-gray-700/60"
                        >
                          {sub}
                        </span>
                      ))}
                    </div>

                    <div className="flex items-center gap-3 text-gray-400">
                      <span>
                        Expected Rules: <strong className="text-gray-200">{scen.expected_rules.length}</strong>
                      </span>
                      <span>
                        Alerts: <strong className="text-gray-200">{scen.expected_alerts}</strong>
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right Column: Active Simulation & Live Telemetry Stepper (5 cols) */}
          <div className="lg:col-span-5 space-y-4">
            {activeRun ? (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-5 sticky top-6">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <div>
                    <span className="text-xs text-gray-500 font-mono">LATEST EXECUTION</span>
                    <h2 className="text-base font-bold text-white mt-0.5">{activeRun.scenario_name}</h2>
                  </div>

                  <span
                    className={`text-xs px-2.5 py-1 rounded-full font-bold uppercase tracking-wider border ${
                      activeRun.status === 'PASSED'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : activeRun.status === 'PARTIAL'
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : activeRun.status === 'RUNNING'
                        ? 'bg-blue-500/10 text-blue-400 border-blue-500/30 animate-pulse'
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    }`}
                  >
                    {activeRun.status}
                  </span>
                </div>

                {/* Accuracy Score Pill Box */}
                {activeRun.result && (
                  <div className="grid grid-cols-4 gap-2 bg-gray-950/60 border border-gray-800/80 rounded-lg p-3 text-center">
                    <div>
                      <div className="text-[10px] text-gray-400 uppercase font-semibold">Precision</div>
                      <div className="text-sm font-bold text-white mt-0.5">
                        {(activeRun.result.precision * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-400 uppercase font-semibold">Recall</div>
                      <div className="text-sm font-bold text-white mt-0.5">
                        {(activeRun.result.recall * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-400 uppercase font-semibold">F1 Score</div>
                      <div className="text-sm font-bold text-white mt-0.5">
                        {(activeRun.result.f1_score * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-400 uppercase font-semibold">Latency</div>
                      <div className="text-sm font-bold text-white mt-0.5">
                        {activeRun.result.latency_ms.toFixed(0)}ms
                      </div>
                    </div>
                  </div>
                )}

                {/* Rule Matching Comparison */}
                {activeRun.result && (
                  <div className="space-y-2 text-xs">
                    <div className="text-gray-400 font-semibold uppercase tracking-wider text-[11px]">
                      Detection Rule Validation
                    </div>

                    <div className="space-y-1.5">
                      {activeRun.result.matched_rules.map((rule) => (
                        <div
                          key={rule}
                          className="flex items-center justify-between p-2 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-300"
                        >
                          <span className="font-mono">{rule}</span>
                          <span className="text-[10px] font-bold uppercase tracking-wider">MATCHED (TP)</span>
                        </div>
                      ))}

                      {activeRun.result.unmatched_rules.map((rule) => (
                        <div
                          key={rule}
                          className="flex items-center justify-between p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300"
                        >
                          <span className="font-mono">{rule}</span>
                          <span className="text-[10px] font-bold uppercase tracking-wider">MISSED (FN)</span>
                        </div>
                      ))}

                      {activeRun.result.unexpected_rules.map((rule) => (
                        <div
                          key={rule}
                          className="flex items-center justify-between p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300"
                        >
                          <span className="font-mono">{rule}</span>
                          <span className="text-[10px] font-bold uppercase tracking-wider">UNEXPECTED (FP)</span>
                        </div>
                      ))}

                      {activeRun.result.matched_rules.length === 0 &&
                        activeRun.result.unmatched_rules.length === 0 && (
                          <div className="p-2.5 rounded bg-gray-800/60 text-gray-400 text-center text-xs">
                            Negative Control: Zero unexpected detections confirmed.
                          </div>
                        )}
                    </div>
                  </div>
                )}

                {/* Step Timeline Log */}
                <div className="space-y-2">
                  <div className="text-gray-400 font-semibold uppercase tracking-wider text-[11px]">
                    Sandbox Execution Timeline
                  </div>
                  <div className="bg-gray-950 rounded-lg p-3 border border-gray-800/80 max-h-56 overflow-y-auto space-y-2 text-xs font-mono">
                    {activeRun.execution_logs.map((log) => (
                      <div key={log.step_number} className="flex items-start gap-2">
                        <span className="text-gray-500">[{log.step_number}]</span>
                        <span
                          className={`font-semibold ${
                            log.status === 'SUCCESS'
                              ? 'text-emerald-400'
                              : log.status === 'ERROR'
                              ? 'text-rose-400'
                              : log.status === 'WARN'
                              ? 'text-amber-400'
                              : 'text-blue-400'
                          }`}
                        >
                          {log.action}:
                        </span>
                        <span className="text-gray-300 flex-1">{log.message}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Audit Report Action */}
                <button
                  onClick={() => handleViewReport(activeRun.id)}
                  disabled={loadingReport}
                  className="w-full flex items-center justify-center gap-2 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-semibold border border-gray-700 transition"
                >
                  <FileText className="w-4 h-4 text-emerald-400" />
                  View Security Audit Report (.md)
                </button>
              </div>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-400">
                <FlaskConical className="w-10 h-10 mx-auto text-gray-600 mb-3" />
                <p className="text-sm">Select or execute a scenario to view real-time validation telemetry.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Subsystem Coverage Matrix */}
      {activeTab === 'coverage' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Platform Subsystem Coverage Matrix</h2>
            <span className="text-xs text-gray-400 font-mono">11 Scenarios Evaluated</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase tracking-wider font-semibold border-b border-gray-800">
                <tr>
                  <th className="p-3.5">Scenario</th>
                  <th className="p-3.5">Target Subsystem</th>
                  <th className="p-3.5">Coverage Status</th>
                  <th className="p-3.5">Evaluated Detection Rules</th>
                  <th className="p-3.5">Defensive Heuristic Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/80">
                {coverage.map((item, idx) => (
                  <tr key={`${item.scenario_id}-${item.subsystem}-${idx}`} className="hover:bg-gray-800/40">
                    <td className="p-3.5 font-medium text-white whitespace-nowrap">
                      <span className="font-mono text-gray-400 mr-2">{item.scenario_id}</span>
                      {item.scenario_name}
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-gray-800 text-gray-300 border border-gray-700">
                        {item.subsystem}
                      </span>
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                          item.coverage_level === 'SUPPORTED'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : item.coverage_level === 'PARTIALLY_SUPPORTED'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {item.coverage_level}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <div className="flex flex-wrap gap-1">
                        {item.rules_evaluated.map((r) => (
                          <span key={r} className="font-mono text-[10px] px-1.5 py-0.5 bg-gray-950 rounded text-gray-300 border border-gray-800">
                            {r}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3.5 text-gray-400 leading-normal">{item.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Execution History */}
      {activeTab === 'history' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Historical Validation Runs</h2>
            <span className="text-xs text-gray-400">Past {runs.length} Executions</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase tracking-wider font-semibold border-b border-gray-800">
                <tr>
                  <th className="p-3.5">Run ID</th>
                  <th className="p-3.5">Scenario</th>
                  <th className="p-3.5">Pass Status</th>
                  <th className="p-3.5">Precision / Recall</th>
                  <th className="p-3.5">Duration</th>
                  <th className="p-3.5">Executed At</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/80">
                {runs.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-800/40">
                    <td className="p-3.5 font-mono text-gray-400">{r.id.slice(0, 8)}</td>
                    <td className="p-3.5 font-medium text-white">
                      <span className="font-mono text-gray-400 mr-2">{r.scenario_id}</span>
                      {r.scenario_name}
                    </td>
                    <td className="p-3.5">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                          r.status === 'PASSED'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : r.status === 'PARTIAL'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-gray-300 font-mono">
                      {r.result
                        ? `${(r.result.precision * 100).toFixed(0)}% / ${(r.result.recall * 100).toFixed(0)}%`
                        : 'N/A'}
                    </td>
                    <td className="p-3.5 text-gray-400 font-mono">{r.duration_ms} ms</td>
                    <td className="p-3.5 text-gray-400">
                      {r.completed_at ? new Date(r.completed_at).toLocaleString() : 'In Progress'}
                    </td>
                    <td className="p-3.5 text-right">
                      <button
                        onClick={() => handleViewReport(r.id)}
                        className="text-emerald-400 hover:text-emerald-300 font-medium transition"
                      >
                        View Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Markdown Audit Report Modal / Drawer */}
      {selectedReport && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-white text-base">{selectedReport.title}</h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyReport}
                  className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded text-xs transition"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedReport ? 'Copied' : 'Copy Markdown'}
                </button>

                <button
                  onClick={handleDownloadReport}
                  className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded text-xs transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download
                </button>

                <button
                  onClick={() => setSelectedReport(null)}
                  className="p-1.5 text-gray-400 hover:text-white rounded hover:bg-gray-800 transition"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto font-mono text-xs text-gray-300 leading-relaxed bg-gray-950 space-y-4">
              <pre className="whitespace-pre-wrap">{selectedReport.markdown_content}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
