import React, { useState, useEffect, useCallback } from 'react';
import {
  ClassifiedFileOverviewItem,
  DetectionRuleInfo,
  FileClassificationDetail,
  SensitivitySummaryResponse,
} from '../types/detection';
import { ScanJobSummary } from '../types/scanner';
import {
  fetchClassifiedFiles,
  fetchDetectionRules,
  fetchFileClassificationDetail,
  fetchScanHistory,
  fetchSensitivitySummary,
} from '../services/api';

export const SensitiveDataPage: React.FC = () => {
  // Scans & active selection
  const [scanHistory, setScanHistory] = useState<ScanJobSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [loadingScans, setLoadingScans] = useState<boolean>(true);

  // Summary and Rules
  const [summary, setSummary] = useState<SensitivitySummaryResponse | null>(null);
  const [rules, setRules] = useState<DetectionRuleInfo[]>([]);
  const [showRulesModal, setShowRulesModal] = useState<boolean>(false);
  const [loadingSummary, setLoadingSummary] = useState<boolean>(false);

  // Classified files inventory & pagination
  const [classifiedFiles, setClassifiedFiles] = useState<ClassifiedFileOverviewItem[]>([]);
  const [totalFiles, setTotalFiles] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loadingFiles, setLoadingFiles] = useState<boolean>(false);

  // Filters
  const [sensitivityFilter, setSensitivityFilter] = useState<string>('');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected file details drawer
  const [selectedFileDetail, setSelectedFileDetail] = useState<FileClassificationDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);

  // General error banner
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load Scan History and Rules on mount
  useEffect(() => {
    const initData = async () => {
      try {
        setLoadingScans(true);
        const [history, rulesData] = await Promise.all([
          fetchScanHistory(20),
          fetchDetectionRules(),
        ]);
        setScanHistory(history);
        setRules(rulesData);
        if (history.length > 0) {
          // Select the latest completed scan, or the first scan
          const completedScan = history.find(s => s.status === 'completed') || history[0];
          setSelectedScanId(completedScan.id);
        }
      } catch (err: any) {
        setErrorMessage(err.message || 'Failed to initialize detection dashboard');
      } finally {
        setLoadingScans(false);
      }
    };

    initData();
  }, []);

  // Fetch summary and classified files when scan ID or filters change
  const loadScanData = useCallback(async (scanId: string) => {
    if (!scanId) return;

    try {
      setLoadingSummary(true);
      setErrorMessage(null);
      const summaryData = await fetchSensitivitySummary(scanId).catch(() => null);
      setSummary(summaryData);
    } catch (err: any) {
      setErrorMessage(err.message || 'Error fetching sensitivity summary');
    } finally {
      setLoadingSummary(false);
    }
  }, []);

  const loadFiles = useCallback(async (scanId: string, pageNum: number) => {
    if (!scanId) return;

    try {
      setLoadingFiles(true);
      const filesResp = await fetchClassifiedFiles(
        scanId,
        pageNum,
        25,
        sensitivityFilter || undefined,
        categoryFilter || undefined,
        searchQuery || undefined,
        confidenceFilter || undefined
      );
      setClassifiedFiles(filesResp.items);
      setTotalFiles(filesResp.total);
      setTotalPages(filesResp.pages);
    } catch (err: any) {
      setErrorMessage(err.message || 'Error fetching classified file inventory');
    } finally {
      setLoadingFiles(false);
    }
  }, [sensitivityFilter, categoryFilter, searchQuery, confidenceFilter]);

  useEffect(() => {
    if (selectedScanId) {
      loadScanData(selectedScanId);
      loadFiles(selectedScanId, page);
    }
  }, [selectedScanId, loadScanData, loadFiles, page]);

  const handleScanChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSelectedScanId(e.target.value);
    setPage(1);
  };

  const handleInspectFile = async (fileId: string) => {
    try {
      setLoadingDetail(true);
      setErrorDetail(null);
      const detail = await fetchFileClassificationDetail(fileId);
      setSelectedFileDetail(detail);
    } catch (err: any) {
      setErrorDetail(err.message || 'Failed to load file classification audit');
    } finally {
      setLoadingDetail(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const renderSensitivityBadge = (label: string) => {
    let bg = 'rgba(100, 116, 139, 0.15)';
    let text = 'var(--text-muted)';
    let border = 'rgba(100, 116, 139, 0.3)';

    if (label === 'RESTRICTED') {
      bg = 'rgba(239, 68, 68, 0.15)';
      text = 'var(--accent-red)';
      border = 'rgba(239, 68, 68, 0.4)';
    } else if (label === 'CONFIDENTIAL') {
      bg = 'rgba(245, 158, 11, 0.15)';
      text = 'var(--accent-amber)';
      border = 'rgba(245, 158, 11, 0.4)';
    } else if (label === 'INTERNAL') {
      bg = 'rgba(56, 189, 248, 0.15)';
      text = 'var(--accent-blue)';
      border = 'rgba(56, 189, 248, 0.4)';
    } else if (label === 'PUBLIC') {
      bg = 'rgba(16, 185, 129, 0.15)';
      text = 'var(--accent-green)';
      border = 'rgba(16, 185, 129, 0.4)';
    }

    return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.2rem 0.6rem',
        borderRadius: '6px',
        fontSize: '0.75rem',
        fontWeight: 700,
        letterSpacing: '0.04em',
        backgroundColor: bg,
        color: text,
        border: `1px solid ${border}`,
        textTransform: 'uppercase',
      }}>
        {label === 'RESTRICTED' && '🛡️'}
        {label === 'CONFIDENTIAL' && '🔒'}
        {label === 'INTERNAL' && '🏢'}
        {label === 'PUBLIC' && '🌐'}
        {label === 'NOT_ASSESSED' && '⚪'}
        {label}
      </span>
    );
  };

  const renderConfidenceBadge = (confidence: string) => {
    let color = 'var(--text-muted)';
    let bg = 'rgba(100, 116, 139, 0.1)';

    if (confidence === 'HIGH') {
      color = 'var(--accent-green)';
      bg = 'rgba(16, 185, 129, 0.1)';
    } else if (confidence === 'MEDIUM') {
      color = 'var(--accent-amber)';
      bg = 'rgba(245, 158, 11, 0.1)';
    } else if (confidence === 'LOW') {
      color = 'var(--accent-blue)';
      bg = 'rgba(56, 189, 248, 0.1)';
    }

    return (
      <span style={{
        fontSize: '0.7rem',
        fontWeight: 600,
        padding: '0.15rem 0.45rem',
        borderRadius: '4px',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${color}33`,
      }}>
        {confidence}
      </span>
    );
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '2rem' }}>
      {/* Header bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '2rem',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Sensitive Data & Classification Engine
            </h1>
            <span style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.2rem 0.5rem',
              borderRadius: '4px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              color: 'var(--accent-green)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}>
              Phase 3 Live
            </span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Deterministic pattern matching, cryptographic validation, and multi-tier sensitivity classification.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {/* Scan run selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500 }}>
              Scan Run:
            </label>
            <select
              value={selectedScanId}
              onChange={handleScanChange}
              disabled={loadingScans}
              style={{
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-active)',
                borderRadius: '6px',
                padding: '0.45rem 0.85rem',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              {scanHistory.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.root_id} — {new Date(s.started_at).toLocaleTimeString()} ({s.status})
                </option>
              ))}
              {scanHistory.length === 0 && (
                <option value="">No scans recorded yet</option>
              )}
            </select>
          </div>

          <button
            onClick={() => setShowRulesModal(true)}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              borderRadius: '6px',
              border: '1px solid var(--border-active)',
              fontSize: '0.85rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>📜</span> View Detection Rules ({rules.length})
          </button>

          <button
            onClick={() => {
              if (selectedScanId) {
                loadScanData(selectedScanId);
                loadFiles(selectedScanId, page);
              }
            }}
            style={{
              padding: '0.5rem 0.85rem',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.85rem',
            }}
            title="Refresh"
          >
            🔄
          </button>
        </div>
      </div>

      {/* Error message */}
      {errorMessage && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '0.85rem 1.25rem',
          marginBottom: '1.5rem',
          color: 'var(--accent-red)',
          fontSize: '0.875rem',
        }}>
          ⚠️ {errorMessage}
        </div>
      )}

      {/* KPI Overview Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}>
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Files Inspected
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.35rem' }}>
            {loadingSummary ? '...' : (summary ? summary.files_inspected : 0)}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Deep content extraction
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Sensitive Files
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.35rem' }}>
            {summary ? summary.sensitive_files_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Restricted or Confidential
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
          background: 'linear-gradient(180deg, rgba(239, 68, 68, 0.05) 0%, var(--bg-card) 100%)',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 700, textTransform: 'uppercase' }}>
            Restricted
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-red)', marginTop: '0.35rem' }}>
            {summary ? summary.restricted_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Secrets, Keys, Cards
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
          background: 'linear-gradient(180deg, rgba(245, 158, 11, 0.05) 0%, var(--bg-card) 100%)',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-amber)', fontWeight: 700, textTransform: 'uppercase' }}>
            Confidential
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.35rem' }}>
            {summary ? summary.confidential_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            PII, Financials, Banners
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase' }}>
            Internal
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-blue)', marginTop: '0.35rem' }}>
            {summary ? summary.internal_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Safe enterprise assets
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-green)', fontWeight: 600, textTransform: 'uppercase' }}>
            Public
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-green)', marginTop: '0.35rem' }}>
            {summary ? summary.public_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Readme / Public documentation
          </span>
        </div>
      </div>

      {/* Category Breakdown Tiles */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: '1rem',
        marginBottom: '2rem',
      }}>
        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          padding: '1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
        }}>
          <div style={{
            fontSize: '1.5rem',
            backgroundColor: 'rgba(56, 189, 248, 0.1)',
            padding: '0.75rem',
            borderRadius: '8px',
            border: '1px solid rgba(56, 189, 248, 0.25)',
          }}>
            👤
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              PERSONAL INFORMATION (PII)
            </div>
            <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {summary ? summary.pii_count : 0} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-secondary)' }}>detections</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Emails, Pakistani CNIC, Mobile Phones
            </div>
          </div>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          padding: '1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
        }}>
          <div style={{
            fontSize: '1.5rem',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            padding: '0.75rem',
            borderRadius: '8px',
            border: '1px solid rgba(239, 68, 68, 0.25)',
          }}>
            🔑
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              CREDENTIALS & SECRETS
            </div>
            <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {summary ? summary.credential_count : 0} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-secondary)' }}>detections</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Private Keys, API Tokens, Passwords, DB Strings
            </div>
          </div>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          padding: '1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
        }}>
          <div style={{
            fontSize: '1.5rem',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            padding: '0.75rem',
            borderRadius: '8px',
            border: '1px solid rgba(245, 158, 11, 0.25)',
          }}>
            💳
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              FINANCIAL DATA
            </div>
            <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {summary ? summary.financial_count : 0} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-secondary)' }}>detections</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Luhn-Valid Cards, IBAN MOD-97, Salaries
            </div>
          </div>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          padding: '1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
        }}>
          <div style={{
            fontSize: '1.5rem',
            backgroundColor: 'rgba(168, 85, 247, 0.1)',
            padding: '0.75rem',
            borderRadius: '8px',
            border: '1px solid rgba(168, 85, 247, 0.25)',
          }}>
            📑
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              CONFIDENTIAL LABELS
            </div>
            <div style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {summary ? summary.confidential_label_count : 0} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-secondary)' }}>detections</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              STRICTLY CONFIDENTIAL, PROPRIETARY, RESTRICTED
            </div>
          </div>
        </div>
      </div>

      {/* Main Section: Classified File Inventory */}
      <div style={{
        backgroundColor: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--border-subtle)',
        overflow: 'hidden',
      }}>
        {/* Table controls & filter bar */}
        <div style={{
          padding: '1rem 1.5rem',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Classified File Inventory
            </h2>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Showing {classifiedFiles.length} of {totalFiles} records
            </span>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search filename..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
              style={{
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
                outline: 'none',
                width: '180px',
              }}
            />

            <select
              value={sensitivityFilter}
              onChange={(e) => { setSensitivityFilter(e.target.value); setPage(1); }}
              style={{
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              <option value="">All Sensitivities</option>
              <option value="RESTRICTED">Restricted</option>
              <option value="CONFIDENTIAL">Confidential</option>
              <option value="INTERNAL">Internal</option>
              <option value="PUBLIC">Public</option>
              <option value="NOT_ASSESSED">Not Assessed</option>
            </select>

            <select
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
              style={{
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              <option value="">All Confidences</option>
              <option value="HIGH">High Confidence</option>
              <option value="MEDIUM">Medium Confidence</option>
              <option value="LOW">Low Confidence</option>
            </select>

            <select
              value={categoryFilter}
              onChange={(e) => { setCategoryFilter(e.target.value); setPage(1); }}
              style={{
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              <option value="">All Categories</option>
              <option value="Personal Information">Personal Information (PII)</option>
              <option value="Credentials & Secrets">Credentials & Secrets</option>
              <option value="Financial Data">Financial Data</option>
              <option value="Confidential Document Markers">Document Markers</option>
            </select>
          </div>
        </div>

        {/* Table content */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{
                backgroundColor: 'var(--bg-card)',
                borderBottom: '1px solid var(--border-subtle)',
                color: 'var(--text-muted)',
                fontWeight: 600,
              }}>
                <th style={{ padding: '0.75rem 1.25rem' }}>File & Path</th>
                <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                <th style={{ padding: '0.75rem 1rem' }}>Size</th>
                <th style={{ padding: '0.75rem 1rem' }}>Sensitivity Label</th>
                <th style={{ padding: '0.75rem 1rem' }}>Confidence</th>
                <th style={{ padding: '0.75rem 1rem' }}>Findings</th>
                <th style={{ padding: '0.75rem 1.25rem', textAlign: 'right' }}>Audit Action</th>
              </tr>
            </thead>
            <tbody>
              {classifiedFiles.map((file) => (
                <tr
                  key={file.file_id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <td style={{ padding: '0.85rem 1.25rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {file.filename}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {file.relative_path}
                    </div>
                  </td>
                  <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>
                    {file.detected_type}
                  </td>
                  <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>
                    {formatBytes(file.size_bytes)}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {renderSensitivityBadge(file.sensitivity_label)}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {renderConfidenceBadge(file.highest_confidence)}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {file.findings_count > 0 ? (
                      <span style={{
                        padding: '0.15rem 0.5rem',
                        borderRadius: '9999px',
                        backgroundColor: 'rgba(239, 68, 68, 0.15)',
                        color: 'var(--accent-red)',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}>
                        {file.findings_count} match{file.findings_count > 1 ? 'es' : ''}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>None</span>
                    )}
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                    <button
                      onClick={() => handleInspectFile(file.file_id)}
                      style={{
                        padding: '0.35rem 0.75rem',
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--accent-blue)',
                        borderRadius: '4px',
                        border: '1px solid var(--border-active)',
                        fontSize: '0.75rem',
                        fontWeight: 500,
                      }}
                    >
                      Audit Details 🔍
                    </button>
                  </td>
                </tr>
              ))}

              {classifiedFiles.length === 0 && !loadingFiles && (
                <tr>
                  <td colSpan={7} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No files found matching the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.85rem',
          color: 'var(--text-secondary)',
        }}>
          <div>
            Page {page} of {totalPages || 1}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              style={{
                padding: '0.4rem 0.8rem',
                backgroundColor: 'var(--bg-card)',
                color: page <= 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '4px',
                cursor: page <= 1 ? 'not-allowed' : 'pointer',
              }}
            >
              Previous
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              style={{
                padding: '0.4rem 0.8rem',
                backgroundColor: 'var(--bg-card)',
                color: page >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '4px',
                cursor: page >= totalPages ? 'not-allowed' : 'pointer',
              }}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Zero-Leakage File Detail Inspection Drawer / Modal */}
      {loadingDetail && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000,
          color: 'var(--text-primary)',
          fontSize: '1rem',
          fontWeight: 600,
        }}>
          Loading file classification details...
        </div>
      )}

      {selectedFileDetail && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'flex-end',
          zIndex: 1000,
        }}>
          <div style={{
            width: '100%',
            maxWidth: '680px',
            backgroundColor: 'var(--bg-secondary)',
            height: '100%',
            overflowY: 'auto',
            borderLeft: '1px solid var(--border-active)',
            padding: '2rem',
            display: 'flex',
            flexDirection: 'column',
          }}>
            {errorDetail && (
              <div style={{
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--accent-red)',
                padding: '0.75rem',
                borderRadius: '6px',
                color: 'var(--accent-red)',
                marginBottom: '1rem',
                fontSize: '0.85rem',
              }}>
                {errorDetail}
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase' }}>
                  Auditable File Classification
                </span>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  {selectedFileDetail.filename}
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {selectedFileDetail.relative_path}
                </p>
              </div>
              <button
                onClick={() => setSelectedFileDetail(null)}
                style={{
                  padding: '0.4rem 0.75rem',
                  backgroundColor: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.9rem',
                }}
              >
                ✕ Close
              </button>
            </div>

            {/* Zero-Leakage Privacy Callout */}
            <div style={{
              backgroundColor: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              marginBottom: '1.5rem',
              fontSize: '0.8rem',
              color: 'var(--accent-green)',
            }}>
              🔒 <strong>Zero-Leakage Privacy Policy:</strong> SentinelDLP records only rule triggers, occurrence frequencies, and confidence ratings. Raw secrets, card numbers, and PII values are discarded immediately from system memory.
            </div>

            {/* Classification Outcome Summary */}
            <div style={{
              backgroundColor: 'var(--bg-card)',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              padding: '1.25rem',
              marginBottom: '1.5rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Assigned Classification:</span>
                {renderSensitivityBadge(selectedFileDetail.classification.sensitivity_label)}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Highest Trigger Confidence:</span>
                {renderConfidenceBadge(selectedFileDetail.classification.highest_confidence)}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Policy Version:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                  {selectedFileDetail.classification.policy_version}
                </span>
              </div>
              <div>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Auditable Explanation:
                </span>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'var(--bg-primary)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.85rem',
                  color: 'var(--text-primary)',
                  lineHeight: 1.5,
                }}>
                  {selectedFileDetail.classification.explanation}
                </div>
              </div>
            </div>

            {/* Findings Breakdown */}
            <div style={{ flex: 1 }}>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
                Detection Findings ({selectedFileDetail.findings.length})
              </h4>

              {selectedFileDetail.findings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.85rem 1rem',
                    marginBottom: '0.75rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                      {f.rule_id}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Category: {f.category} • Occurrences: <strong>{f.occurrence_count}</strong>
                    </div>
                  </div>
                  <div>
                    {renderConfidenceBadge(f.confidence)}
                  </div>
                </div>
              ))}

              {selectedFileDetail.findings.length === 0 && (
                <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  No sensitive patterns or credentials detected in this file.
                </div>
              )}
            </div>

            {/* Cryptographic Integrity Footer */}
            <div style={{
              marginTop: '1.5rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--border-subtle)',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
            }}>
              <div>SHA-256 Digest:</div>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                {selectedFileDetail.sha256_hash || 'Hash not computed'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Rules Catalog Modal */}
      {showRulesModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000,
          padding: '1rem',
        }}>
          <div style={{
            width: '100%',
            maxWidth: '850px',
            backgroundColor: 'var(--bg-secondary)',
            borderRadius: '12px',
            border: '1px solid var(--border-active)',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '1.25rem 1.75rem',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Active Sensitive Data Detection Rules
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Version-controlled policy registry enforcing zero sensitive content disclosure
                </p>
              </div>
              <button
                onClick={() => setShowRulesModal(false)}
                style={{
                  padding: '0.4rem 0.75rem',
                  backgroundColor: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.85rem',
                }}
              >
                ✕ Close
              </button>
            </div>

            <div style={{ padding: '1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    padding: '1rem 1.25rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--accent-blue)', fontWeight: 600 }}>
                        {rule.id}
                      </div>
                      <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {rule.name}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      {renderSensitivityBadge(rule.suggested_classification)}
                      {renderConfidenceBadge(rule.confidence)}
                    </div>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                    {rule.description}
                  </p>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                    Category: <strong>{rule.category}</strong>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
