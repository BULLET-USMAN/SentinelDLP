import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  cancelScanJob,
  createScanJob,
  fetchAuthorizedRoots,
  fetchScanFiles,
  fetchScanHistory,
  fetchScanStatus,
} from '../services/api';
import {
  AuthorizedRoot,
  PaginatedFilesResponse,
  ScanJobSummary,
} from '../types/scanner';

export const FileScannerPage: React.FC = () => {
  // Roots & Job Selection
  const [roots, setRoots] = useState<AuthorizedRoot[]>([]);
  const [selectedRootId, setSelectedRootId] = useState<string>('');
  const [activeJob, setActiveJob] = useState<ScanJobSummary | null>(null);
  const [history, setHistory] = useState<ScanJobSummary[]>([]);

  // Inventory Table State
  const [filesData, setFilesData] = useState<PaginatedFilesResponse | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize] = useState<number>(25);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterMismatch, setFilterMismatch] = useState<boolean>(false);

  // Status & Polling
  const [isLoadingRoots, setIsLoadingRoots] = useState<boolean>(true);
  const [isLoadingFiles, setIsLoadingFiles] = useState<boolean>(false);
  const [isActionPending, setIsActionPending] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const activeJobIdRef = useRef<string | null>(null);
  activeJobIdRef.current = activeJob?.id || null;

  // 1. Initial Load: Roots & History
  const loadInitialData = useCallback(async () => {
    setIsLoadingRoots(true);
    setErrorMessage(null);
    try {
      const [fetchedRoots, fetchedHistory] = await Promise.all([
        fetchAuthorizedRoots(),
        fetchScanHistory(10),
      ]);
      setRoots(fetchedRoots);
      if (fetchedRoots.length > 0 && !selectedRootId) {
        setSelectedRootId(fetchedRoots[0].root_id);
      }
      setHistory(fetchedHistory);
      if (fetchedHistory.length > 0 && !activeJob) {
        setActiveJob(fetchedHistory[0]);
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to initialize scanner');
    } finally {
      setIsLoadingRoots(false);
    }
  }, [selectedRootId, activeJob]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // 2. Load Paginated Files for Active Job
  const loadJobFiles = useCallback(async (jobId: string, page: number) => {
    setIsLoadingFiles(true);
    try {
      const data = await fetchScanFiles(
        jobId,
        page,
        pageSize,
        searchTerm || undefined,
        filterType || undefined,
        filterStatus || undefined,
        filterMismatch ? true : undefined
      );
      setFilesData(data);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to load file records');
    } finally {
      setIsLoadingFiles(false);
    }
  }, [pageSize, searchTerm, filterType, filterStatus, filterMismatch]);

  useEffect(() => {
    if (activeJob?.id) {
      loadJobFiles(activeJob.id, currentPage);
    }
  }, [activeJob?.id, currentPage, loadJobFiles]);

  // 3. Polling when Scan is Running
  useEffect(() => {
    if (!activeJob || (activeJob.status !== 'running' && activeJob.status !== 'pending')) {
      return;
    }

    const intervalId = setInterval(async () => {
      try {
        const updatedStatus = await fetchScanStatus(activeJob.id);
        setActiveJob(updatedStatus);

        // If completed or state changed, refresh history and files
        if (updatedStatus.status !== 'running' && updatedStatus.status !== 'pending') {
          const freshHistory = await fetchScanHistory(10);
          setHistory(freshHistory);
          loadJobFiles(updatedStatus.id, 1);
        }
      } catch {
        // Suppress transient poll error
      }
    }, 1500);

    return () => clearInterval(intervalId);
  }, [activeJob, loadJobFiles]);

  // Handlers
  const handleStartScan = async () => {
    if (!selectedRootId) return;
    setIsActionPending(true);
    setErrorMessage(null);
    try {
      const newJob = await createScanJob(selectedRootId);
      setActiveJob(newJob);
      setCurrentPage(1);
      const updatedHistory = await fetchScanHistory(10);
      setHistory(updatedHistory);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Could not trigger scan');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleCancelScan = async () => {
    if (!activeJob) return;
    setIsActionPending(true);
    try {
      await cancelScanJob(activeJob.id);
      const updated = await fetchScanStatus(activeJob.id);
      setActiveJob(updated);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to cancel scan');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const isScanning = activeJob?.status === 'running' || activeJob?.status === 'pending';
  const selectedRootMeta = roots.find((r) => r.root_id === selectedRootId);

  return (
    <div style={{ maxWidth: '1350px', margin: '0 auto', padding: '2rem 1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '1rem',
        marginBottom: '2rem',
        paddingBottom: '1.5rem',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            Intelligent File Scanner & Inventory
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Phase 2: Secure boundary discovery, streaming SHA-256 verification, and file type discrepancy detection.
          </p>
        </div>

        {/* Global Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <select
            value={selectedRootId}
            onChange={(e) => setSelectedRootId(e.target.value)}
            disabled={isScanning || isLoadingRoots}
            style={{
              padding: '0.55rem 1rem',
              backgroundColor: 'var(--bg-card)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-active)',
              borderRadius: '6px',
              fontSize: '0.875rem',
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            {roots.map((r) => (
              <option key={r.root_id} value={r.root_id}>
                {r.name} ({r.root_id})
              </option>
            ))}
          </select>

          <button
            onClick={handleStartScan}
            disabled={isScanning || isActionPending || !selectedRootId}
            style={{
              padding: '0.55rem 1.25rem',
              backgroundColor: isScanning ? 'var(--bg-tertiary)' : 'var(--accent-green)',
              color: isScanning ? 'var(--text-muted)' : '#041d14',
              fontWeight: 600,
              borderRadius: '6px',
              fontSize: '0.875rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              boxShadow: isScanning ? 'none' : '0 0 12px rgba(16, 185, 129, 0.25)',
            }}
          >
            {isScanning ? (
              <>
                <span style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--accent-green)',
                  animation: 'pulse 1.5s infinite',
                }} />
                Scanning...
              </>
            ) : (
              'Start Scan'
            )}
          </button>

          {isScanning && (
            <button
              onClick={handleCancelScan}
              disabled={isActionPending}
              style={{
                padding: '0.55rem 1.25rem',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                color: 'var(--accent-red)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                fontWeight: 600,
                borderRadius: '6px',
                fontSize: '0.875rem',
                cursor: 'pointer',
              }}
            >
              Cancel Scan
            </button>
          )}
        </div>
      </div>

      {/* Selected Root Details */}
      {selectedRootMeta && (
        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '0.75rem 1.25rem',
          marginBottom: '1.5rem',
          fontSize: '0.85rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Authorized Path: </span>
            <code style={{ color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>{selectedRootMeta.path}</code>
          </div>
          <div style={{ color: 'var(--text-secondary)' }}>
            {selectedRootMeta.description}
          </div>
        </div>
      )}

      {/* Error Banner */}
      {errorMessage && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '0.85rem 1.25rem',
          marginBottom: '1.5rem',
          color: 'var(--accent-red)',
          fontSize: '0.85rem',
        }}>
          {errorMessage}
        </div>
      )}

      {/* Active Scan Statistics Cards */}
      {activeJob && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
          marginBottom: '2rem',
        }}>
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Scan Status</span>
            <div style={{ fontSize: '1.15rem', fontWeight: 700, marginTop: '0.35rem', color: activeJob.status === 'completed' ? 'var(--accent-green)' : activeJob.status === 'running' ? 'var(--accent-blue)' : 'var(--accent-amber)' }}>
              {activeJob.status.toUpperCase()}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Discovered</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: 'var(--text-primary)' }}>
              {activeJob.files_discovered}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Processed / Hashed</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: 'var(--accent-green)' }}>
              {activeJob.files_processed}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Skipped</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: activeJob.files_skipped > 0 ? 'var(--accent-amber)' : 'var(--text-muted)' }}>
              {activeJob.files_skipped}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Errors</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: activeJob.error_count > 0 ? 'var(--accent-red)' : 'var(--text-muted)' }}>
              {activeJob.error_count}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Data Volume</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: 'var(--text-primary)' }}>
              {formatBytes(activeJob.total_bytes_processed)}
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Duration</span>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.35rem', color: 'var(--text-secondary)' }}>
              {activeJob.duration_seconds !== null ? `${activeJob.duration_seconds}s` : 'Active'}
            </div>
          </div>
        </div>
      )}

      {/* File Inventory Filter Bar */}
      <div style={{
        backgroundColor: 'var(--bg-secondary)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px 8px 0 0',
        padding: '1rem 1.25rem',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: '1', minWidth: '240px' }}>
          <input
            type="text"
            placeholder="Search discovered filename..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '0.5rem 0.85rem',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-active)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              width: '100%',
              maxWidth: '300px',
              outline: 'none',
            }}
          />

          <select
            value={filterType}
            onChange={(e) => {
              setFilterType(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '0.5rem 0.75rem',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-active)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          >
            <option value="">All File Types</option>
            <option value="Document">Documents (PDF, TXT)</option>
            <option value="Structured">Structured (JSON, CSV, XML)</option>
            <option value="Source Code">Source Code (PY, JS, TS, Java)</option>
            <option value="Configuration">Configuration (ENV, YAML)</option>
            <option value="Image">Images (PNG, JPG)</option>
            <option value="Archive">Archives (ZIP)</option>
          </select>

          <select
            value={filterStatus}
            onChange={(e) => {
              setFilterStatus(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '0.5rem 0.75rem',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-active)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          >
            <option value="">All Statuses</option>
            <option value="scanned">Scanned</option>
            <option value="skipped">Skipped</option>
            <option value="error">Error</option>
          </select>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={filterMismatch}
            onChange={(e) => {
              setFilterMismatch(e.target.checked);
              setCurrentPage(1);
            }}
            style={{ accentColor: 'var(--accent-amber)' }}
          />
          Filter Signature Discrepancies Only
        </label>
      </div>

      {/* File Inventory Table */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderTop: 'none',
        borderRadius: '0 0 8px 8px',
        overflowX: 'auto',
        marginBottom: '2.5rem',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)' }}>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Filename</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Relative Path</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Detected Type</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Size</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Last Modified</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>SHA-256 Digest</th>
              <th style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {isLoadingFiles ? (
              <tr>
                <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading file inventory...
                </td>
              </tr>
            ) : filesData && filesData.items.length > 0 ? (
              filesData.items.map((file) => (
                <tr key={file.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '0.75rem 1rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span>{file.filename}</span>
                      {file.type_mismatch && (
                        <span style={{
                          fontSize: '0.65rem',
                          padding: '0.1rem 0.35rem',
                          borderRadius: '4px',
                          backgroundColor: 'rgba(245, 158, 11, 0.15)',
                          color: 'var(--accent-amber)',
                          border: '1px solid rgba(245, 158, 11, 0.3)',
                          textTransform: 'uppercase',
                        }}>
                          Mismatch
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                    {file.relative_path}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                    {file.detected_type}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {formatBytes(file.size_bytes)}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    {file.modified_at ? new Date(file.modified_at).toLocaleString() : 'N/A'}
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    {file.sha256_hash ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-green)' }}>
                          {file.sha256_hash.substring(0, 12)}...
                        </code>
                        <button
                          onClick={() => handleCopyHash(file.sha256_hash!)}
                          title="Copy Full SHA-256"
                          style={{
                            padding: '0.2rem 0.4rem',
                            backgroundColor: 'transparent',
                            color: copiedHash === file.sha256_hash ? 'var(--accent-green)' : 'var(--text-muted)',
                            fontSize: '0.7rem',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '4px',
                          }}
                        >
                          {copiedHash === file.sha256_hash ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>N/A</span>
                    )}
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span style={{
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      textTransform: 'uppercase',
                      backgroundColor: file.status === 'scanned' ? 'rgba(16, 185, 129, 0.1)' : file.status === 'skipped' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      color: file.status === 'scanned' ? 'var(--accent-green)' : file.status === 'skipped' ? 'var(--accent-amber)' : 'var(--accent-red)',
                      border: `1px solid ${file.status === 'scanned' ? 'rgba(16, 185, 129, 0.25)' : file.status === 'skipped' ? 'rgba(245, 158, 11, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                    }}>
                      {file.status}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No files discovered or matching current search filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {/* Pagination Bar */}
        {filesData && filesData.pages > 1 && (
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '0.75rem 1.25rem',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-secondary)',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}>
            <div>
              Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, filesData.total)} of {filesData.total} files
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '4px',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                  cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                }}
              >
                Previous
              </button>
              <span style={{ padding: '0.35rem 0.5rem' }}>Page {currentPage} of {filesData.pages}</span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(filesData.pages, p + 1))}
                disabled={currentPage === filesData.pages}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '4px',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  color: currentPage === filesData.pages ? 'var(--text-muted)' : 'var(--text-primary)',
                  cursor: currentPage === filesData.pages ? 'not-allowed' : 'pointer',
                }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Historical Scans Section */}
      <div style={{
        backgroundColor: 'var(--bg-secondary)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '1.5rem',
      }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '1rem' }}>
          Historical Scan Jobs
        </h2>
        {history.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Job ID</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Root Target</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Started At</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Duration</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Files</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Status</th>
                  <th style={{ padding: '0.5rem 0.75rem' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {history.map((job) => (
                  <tr key={job.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.65rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-blue)' }}>
                      {job.id.substring(0, 8)}...
                    </td>
                    <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-primary)' }}>{job.root_id}</td>
                    <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      {new Date(job.started_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-secondary)' }}>
                      {job.duration_seconds !== null ? `${job.duration_seconds}s` : 'Active'}
                    </td>
                    <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-primary)' }}>
                      {job.files_processed} / {job.files_discovered}
                    </td>
                    <td style={{ padding: '0.65rem 0.75rem' }}>
                      <span style={{
                        fontSize: '0.7rem',
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        textTransform: 'uppercase',
                        backgroundColor: job.status === 'completed' ? 'rgba(16, 185, 129, 0.1)' : job.status === 'running' ? 'rgba(56, 189, 248, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                        color: job.status === 'completed' ? 'var(--accent-green)' : job.status === 'running' ? 'var(--accent-blue)' : 'var(--accent-red)',
                      }}>
                        {job.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 0.75rem' }}>
                      <button
                        onClick={() => {
                          setActiveJob(job);
                          setCurrentPage(1);
                        }}
                        style={{
                          padding: '0.25rem 0.6rem',
                          borderRadius: '4px',
                          backgroundColor: activeJob?.id === job.id ? 'var(--bg-card)' : 'transparent',
                          color: activeJob?.id === job.id ? 'var(--accent-green)' : 'var(--text-muted)',
                          border: '1px solid var(--border-subtle)',
                          fontSize: '0.75rem',
                          cursor: 'pointer',
                        }}
                      >
                        {activeJob?.id === job.id ? 'Viewing' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No historical scan jobs recorded yet. Click "Start Scan" above to run an authorized inventory scan.
          </div>
        )}
      </div>
    </div>
  );
};
