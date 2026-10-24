import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  FileActivityEventItem,
  MonitoringRootInfo,
  MonitoringStatisticsResponse,
  MonitoringStatusResponse,
} from '../types/monitoring';
import {
  createEventSourceStream,
  fetchMonitoringEvents,
  fetchMonitoringRoots,
  fetchMonitoringStatistics,
  fetchMonitoringStatus,
  startMonitoring,
  stopMonitoring,
} from '../services/api';

export const LiveActivityPage: React.FC = () => {
  // Monitoring Roots & Selection
  const [roots, setRoots] = useState<MonitoringRootInfo[]>([]);
  const [selectedRootId, setSelectedRootId] = useState<string>('synthetic_samples');
  const [isRecursive, setIsRecursive] = useState<boolean>(true);

  // Status & Telemetry
  const [statusInfo, setStatusInfo] = useState<MonitoringStatusResponse | null>(null);
  const [stats, setStats] = useState<MonitoringStatisticsResponse | null>(null);
  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);

  // Events & Pagination
  const [events, setEvents] = useState<FileActivityEventItem[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loadingEvents, setLoadingEvents] = useState<boolean>(false);

  // Filters
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('');
  const [sensitivityFilter, setSensitivityFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Event detail modal
  const [selectedEvent, setSelectedEvent] = useState<FileActivityEventItem | null>(null);

  // Alerts
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  // Load roots and initial status
  const loadRootsAndStatus = useCallback(async () => {
    try {
      setErrorMessage(null);
      const [rootsData, statusData, statsData] = await Promise.all([
        fetchMonitoringRoots(),
        fetchMonitoringStatus(selectedRootId),
        fetchMonitoringStatistics(selectedRootId),
      ]);
      setRoots(rootsData);
      setStatusInfo(statusData);
      setStats(statsData);
      if (rootsData.length > 0 && !selectedRootId) {
        setSelectedRootId(rootsData[0].root_id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to initialize monitoring telemetry');
    }
  }, [selectedRootId]);

  // Load events
  const loadEvents = useCallback(async (pageNum: number) => {
    try {
      setLoadingEvents(true);
      const resp = await fetchMonitoringEvents(
        pageNum,
        50,
        selectedRootId || undefined,
        eventTypeFilter || undefined,
        sensitivityFilter || undefined,
        searchQuery || undefined,
        statusFilter || undefined
      );
      setEvents(resp.items);
      setTotalEvents(resp.total);
      setTotalPages(resp.pages);
    } catch (err: any) {
      setErrorMessage(err.message || 'Error fetching activity events');
    } finally {
      setLoadingEvents(false);
    }
  }, [selectedRootId, eventTypeFilter, sensitivityFilter, searchQuery, statusFilter]);

  useEffect(() => {
    loadRootsAndStatus();
  }, [loadRootsAndStatus]);

  useEffect(() => {
    loadEvents(page);
  }, [loadEvents, page]);

  // Setup Server-Sent Events (SSE) Stream
  useEffect(() => {
    if (!selectedRootId) return;

    // Close previous stream if open
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      const sse = createEventSourceStream(selectedRootId);
      eventSourceRef.current = sse;

      sse.addEventListener('activity', (e: MessageEvent) => {
        try {
          const newEvent: FileActivityEventItem = JSON.parse(e.data);
          // Prepend new event to live list if on page 1 and matches filters
          setEvents((prev) => [newEvent, ...prev.slice(0, 49)]);
          setTotalEvents((prev) => prev + 1);
          // Refresh statistics
          fetchMonitoringStatistics(selectedRootId).then(setStats).catch(() => {});
        } catch {}
      });

      sse.onerror = () => {
        // SSE disconnected or backend reconnected
      };
    } catch {}

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, [selectedRootId]);

  // Start Monitoring Handler
  const handleStartMonitoring = async () => {
    if (!selectedRootId) return;
    try {
      setIsActionLoading(true);
      setErrorMessage(null);
      const res = await startMonitoring(selectedRootId, isRecursive);
      setStatusInfo(res);
      setSuccessMessage(`Real-time monitoring started on root '${selectedRootId}'`);
      await loadRootsAndStatus();
      await loadEvents(1);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to start monitoring');
    } finally {
      setIsActionLoading(false);
    }
  };

  // Stop Monitoring Handler
  const handleStopMonitoring = async () => {
    if (!selectedRootId) return;
    try {
      setIsActionLoading(true);
      setErrorMessage(null);
      const res = await stopMonitoring(selectedRootId);
      setStatusInfo(res);
      setSuccessMessage(`Monitoring stopped for root '${selectedRootId}'`);
      await loadRootsAndStatus();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to stop monitoring');
    } finally {
      setIsActionLoading(false);
    }
  };

  const formatBytes = (bytes: number | null) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const renderEventTypeBadge = (eventType: string) => {
    let icon = '📝';
    let bg = 'rgba(56, 189, 248, 0.15)';
    let text = 'var(--accent-blue)';
    let border = 'rgba(56, 189, 248, 0.3)';

    if (eventType.includes('CREATE')) {
      icon = '✨';
      bg = 'rgba(16, 185, 129, 0.15)';
      text = 'var(--accent-green)';
      border = 'rgba(16, 185, 129, 0.3)';
    } else if (eventType.includes('MODIFY')) {
      icon = '✏️';
      bg = 'rgba(245, 158, 11, 0.15)';
      text = 'var(--accent-amber)';
      border = 'rgba(245, 158, 11, 0.3)';
    } else if (eventType.includes('DELETE')) {
      icon = '🗑️';
      bg = 'rgba(239, 68, 68, 0.15)';
      text = 'var(--accent-red)';
      border = 'rgba(239, 68, 68, 0.3)';
    } else if (eventType.includes('RENAME') || eventType.includes('MOVE')) {
      icon = '🔄';
      bg = 'rgba(168, 85, 247, 0.15)';
      text = '#a855f7';
      border = 'rgba(168, 85, 247, 0.3)';
    }

    return (
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.2rem 0.55rem',
        borderRadius: '4px',
        fontSize: '0.75rem',
        fontWeight: 600,
        backgroundColor: bg,
        color: text,
        border: `1px solid ${border}`,
        fontFamily: 'var(--font-mono)',
      }}>
        <span>{icon}</span> {eventType}
      </span>
    );
  };

  const renderSensitivityBadge = (label: string | null) => {
    if (!label) return <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>;

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
        gap: '0.3rem',
        padding: '0.15rem 0.5rem',
        borderRadius: '4px',
        fontSize: '0.7rem',
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
        {label}
      </span>
    );
  };

  const isMonitoringActive = statusInfo?.status === 'active';

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
              Real-Time File Activity Monitoring
            </h1>
            <span style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.2rem 0.5rem',
              borderRadius: '4px',
              backgroundColor: isMonitoringActive ? 'rgba(16, 185, 129, 0.15)' : 'rgba(100, 116, 139, 0.15)',
              color: isMonitoringActive ? 'var(--accent-green)' : 'var(--text-muted)',
              border: `1px solid ${isMonitoringActive ? 'rgba(16, 185, 129, 0.3)' : 'rgba(100, 116, 139, 0.3)'}`,
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}>
              <span style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: isMonitoringActive ? 'var(--accent-green)' : 'var(--text-muted)',
                boxShadow: isMonitoringActive ? '0 0 6px var(--accent-green)' : 'none',
              }} />
              {isMonitoringActive ? 'Active Watcher' : 'Monitoring Inactive'}
            </span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Non-intrusive event observer tracking file creation, modification, deletion, and renaming in authorized roots.
          </p>
        </div>

        {/* Global actions */}
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={() => {
              loadRootsAndStatus();
              loadEvents(page);
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
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Alert Banners */}
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

      {successMessage && (
        <div style={{
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '8px',
          padding: '0.85rem 1.25rem',
          marginBottom: '1.5rem',
          color: 'var(--accent-green)',
          fontSize: '0.875rem',
        }}>
          ✓ {successMessage}
        </div>
      )}

      {/* Control Panel Card */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        borderRadius: '8px',
        border: '1px solid var(--border-subtle)',
        padding: '1.5rem',
        marginBottom: '1.75rem',
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1.25rem',
        }}>
          {/* Target directory selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                Authorized Monitoring Root
              </label>
              <select
                value={selectedRootId}
                onChange={(e) => setSelectedRootId(e.target.value)}
                disabled={isMonitoringActive || isActionLoading}
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-active)',
                  borderRadius: '6px',
                  padding: '0.5rem 0.85rem',
                  fontSize: '0.85rem',
                  outline: 'none',
                  minWidth: '240px',
                }}
              >
                {roots.map((r) => (
                  <option key={r.root_id} value={r.root_id}>
                    {r.name} ({r.root_id})
                  </option>
                ))}
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '1.25rem' }}>
              <input
                type="checkbox"
                id="recursive-toggle"
                checked={isRecursive}
                onChange={(e) => setIsRecursive(e.target.checked)}
                disabled={isMonitoringActive || isActionLoading}
                style={{ cursor: isMonitoringActive ? 'not-allowed' : 'pointer' }}
              />
              <label htmlFor="recursive-toggle" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                Recursive Subdirectories
              </label>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            {!isMonitoringActive ? (
              <button
                onClick={handleStartMonitoring}
                disabled={isActionLoading || !selectedRootId}
                style={{
                  padding: '0.65rem 1.5rem',
                  borderRadius: '6px',
                  backgroundColor: 'var(--accent-green)',
                  color: '#000',
                  fontWeight: 700,
                  fontSize: '0.875rem',
                  cursor: isActionLoading ? 'not-allowed' : 'pointer',
                  opacity: isActionLoading ? 0.7 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: '0 0 12px rgba(16, 185, 129, 0.25)',
                }}
              >
                <span>▶</span> {isActionLoading ? 'Starting...' : 'Start Monitoring'}
              </button>
            ) : (
              <button
                onClick={handleStopMonitoring}
                disabled={isActionLoading}
                style={{
                  padding: '0.65rem 1.5rem',
                  borderRadius: '6px',
                  backgroundColor: 'var(--accent-red)',
                  color: '#fff',
                  fontWeight: 700,
                  fontSize: '0.875rem',
                  cursor: isActionLoading ? 'not-allowed' : 'pointer',
                  opacity: isActionLoading ? 0.7 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <span>⏹</span> {isActionLoading ? 'Stopping...' : 'Stop Monitoring'}
              </button>
            )}
          </div>
        </div>

        {/* Operational Telemetry Sub-bar */}
        {statusInfo && statusInfo.status === 'active' && (
          <div style={{
            marginTop: '1.25rem',
            paddingTop: '1rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            gap: '2rem',
            flexWrap: 'wrap',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Session Started:</span>{' '}
              <strong style={{ color: 'var(--text-primary)' }}>
                {statusInfo.started_at ? new Date(statusInfo.started_at).toLocaleTimeString() : 'N/A'}
              </strong>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Raw Filesystem Notifications:</span>{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{statusInfo.raw_event_count}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Debounced Bursts Suppressed:</span>{' '}
              <strong style={{ color: 'var(--accent-blue)' }}>{statusInfo.deduplicated_count}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Queue Saturation Drops:</span>{' '}
              <strong style={{ color: statusInfo.queue_overflow_count > 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>
                {statusInfo.queue_overflow_count}
              </strong>
            </div>
          </div>
        )}
      </div>

      {/* KPI Metric Tiles */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '1rem',
        marginBottom: '2rem',
      }}>
        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Total Activity Events
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.35rem' }}>
            {stats ? stats.total_events : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Recorded in session history
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-green)', fontWeight: 600, textTransform: 'uppercase' }}>
            Files Created
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-green)', marginTop: '0.35rem' }}>
            {stats ? stats.created_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Observed additions
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-amber)', fontWeight: 600, textTransform: 'uppercase' }}>
            Files Modified
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.35rem' }}>
            {stats ? stats.modified_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Debounced content updates
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 600, textTransform: 'uppercase' }}>
            Files Deleted
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-red)', marginTop: '0.35rem' }}>
            {stats ? stats.deleted_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Inventory marked unavailable
          </span>
        </div>

        <div style={{
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid rgba(168, 85, 247, 0.3)',
          borderRadius: '8px',
          padding: '1.25rem',
        }}>
          <span style={{ fontSize: '0.75rem', color: '#a855f7', fontWeight: 600, textTransform: 'uppercase' }}>
            Renamed / Moved
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#a855f7', marginTop: '0.35rem' }}>
            {stats ? stats.renamed_count : 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Path changes tracked
          </span>
        </div>
      </div>

      {/* Main Section: Live Event Feed Table */}
      <div style={{
        backgroundColor: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--border-subtle)',
        overflow: 'hidden',
      }}>
        {/* Table Filter Controls */}
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
              Live Event Feed
            </h2>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Showing {events.length} of {totalEvents} events
            </span>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search path..."
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
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1); }}
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
              <option value="">All Event Types</option>
              <option value="FILE_CREATED">File Created</option>
              <option value="FILE_MODIFIED">File Modified</option>
              <option value="FILE_DELETED">File Deleted</option>
              <option value="FILE_RENAMED">File Renamed</option>
              <option value="FILE_MOVED">File Moved</option>
              <option value="DIRECTORY_CREATED">Directory Created</option>
              <option value="DIRECTORY_DELETED">Directory Deleted</option>
            </select>

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
            </select>

            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
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
              <option value="">All Statuses</option>
              <option value="processed">Processed</option>
              <option value="ignored">Ignored</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{
                backgroundColor: 'var(--bg-card)',
                borderBottom: '1px solid var(--border-subtle)',
                color: 'var(--text-muted)',
                fontWeight: 600,
              }}>
                <th style={{ padding: '0.75rem 1.25rem' }}>Timestamp</th>
                <th style={{ padding: '0.75rem 1rem' }}>Event Type</th>
                <th style={{ padding: '0.75rem 1rem' }}>Relative Path</th>
                <th style={{ padding: '0.75rem 1rem' }}>Type & Size</th>
                <th style={{ padding: '0.75rem 1rem' }}>Sensitivity Tier</th>
                <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                <th style={{ padding: '0.75rem 1.25rem', textAlign: 'right' }}>Audit</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr
                  key={ev.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    {new Date(ev.occurred_at).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {renderEventTypeBadge(ev.event_type)}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {ev.relative_path}
                    </div>
                    {ev.previous_relative_path && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        from: {ev.previous_relative_path}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>
                    <div>{ev.file_type || (ev.is_directory ? 'Directory' : '—')}</div>
                    {ev.size_bytes !== null && ev.size_bytes !== undefined && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {formatBytes(ev.size_bytes)}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    {renderSensitivityBadge(ev.sensitivity_label)}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: 500,
                      color: ev.status === 'processed' ? 'var(--accent-green)' : ev.status === 'ignored' ? 'var(--text-muted)' : 'var(--accent-red)',
                    }}>
                      {ev.status}
                    </span>
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                    <button
                      onClick={() => setSelectedEvent(ev)}
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
                      Audit 🔍
                    </button>
                  </td>
                </tr>
              ))}

              {events.length === 0 && !loadingEvents && (
                <tr>
                  <td colSpan={7} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No activity events recorded yet for this root. Start monitoring to stream live events.
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

      {/* Event Details Inspection Drawer / Modal */}
      {selectedEvent && (
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
            maxWidth: '650px',
            backgroundColor: 'var(--bg-secondary)',
            height: '100%',
            overflowY: 'auto',
            borderLeft: '1px solid var(--border-active)',
            padding: '2rem',
            display: 'flex',
            flexDirection: 'column',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase' }}>
                  Filesystem Activity Audit Record
                </span>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  {selectedEvent.relative_path}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
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

            {/* Zero-Leakage Guarantee Banner */}
            <div style={{
              backgroundColor: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              marginBottom: '1.5rem',
              fontSize: '0.8rem',
              color: 'var(--accent-green)',
            }}>
              🔒 <strong>Defensive Telemetry Safeguard:</strong> Real-time monitoring captures only filesystem metadata, cryptographic digests, and sensitivity classification transitions. Raw passwords, credit card digits, and confidential contents are strictly excluded.
            </div>

            {/* Event Metrics Table */}
            <div style={{
              backgroundColor: 'var(--bg-card)',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem',
              fontSize: '0.85rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{selectedEvent.id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event Type:</span>
                {renderEventTypeBadge(selectedEvent.event_type)}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sensitivity Classification:</span>
                {renderSensitivityBadge(selectedEvent.sensitivity_label)}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Occurred Timestamp (UTC):</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                  {new Date(selectedEvent.occurred_at).toISOString()}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Processing Status:</span>
                <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{selectedEvent.status}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Observed Source:</span>
                <span style={{ color: 'var(--text-secondary)' }}>{selectedEvent.event_source}</span>
              </div>
              {selectedEvent.previous_relative_path && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Previous Relative Path:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {selectedEvent.previous_relative_path}
                  </span>
                </div>
              )}
            </div>

            {/* Cryptographic Hash Section */}
            {selectedEvent.sha256_hash && (
              <div style={{
                marginTop: '1.5rem',
                backgroundColor: 'var(--bg-card)',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                padding: '1.25rem',
              }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                  Cryptographic Integrity (SHA-256 Digest):
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-blue)', wordBreak: 'break-all' }}>
                  {selectedEvent.sha256_hash}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
