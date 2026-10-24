"""Pydantic Schemas for Real-Time File Activity Monitoring (Phase 4).

Strictly typed API schemas for monitoring controls, activity events,
telemetry, and live activity streams without exposing confidential file contents.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class MonitoringRootInfo(BaseModel):
    """Administrator-configured authorized directory available for real-time monitoring."""

    root_id: str = Field(..., description="Unique authorized root identifier")
    name: str = Field(..., description="Human-readable root title")
    path: str = Field(..., description="Canonical filesystem path")
    description: str = Field(..., description="Security boundary description")
    is_active: bool = Field(False, description="Whether monitoring is currently active on this root")
    session_id: Optional[str] = Field(None, description="Active monitoring session ID if running")


class MonitoringStartRequest(BaseModel):
    """Request payload to initiate real-time monitoring on an authorized directory."""

    root_id: str = Field(..., description="Target authorized root identifier")
    recursive: bool = Field(True, description="Whether to monitor directory subtrees recursively")


class MonitoringStopRequest(BaseModel):
    """Request payload to terminate monitoring on an authorized directory."""

    root_id: str = Field(..., description="Target authorized root identifier to stop")


class MonitoringStatusResponse(BaseModel):
    """Operational status and health telemetry for a monitored root directory."""

    root_id: str
    status: str = Field(..., description="Current status: active, stopped, degraded, failed, starting, stopping")
    session_id: Optional[str] = None
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    raw_event_count: int = 0
    processed_event_count: int = 0
    deduplicated_count: int = 0
    queue_overflow_count: int = 0
    last_event_at: Optional[datetime] = None
    last_error: Optional[str] = None


class FileActivityEventItem(BaseModel):
    """Normalized file or directory activity event."""

    id: str
    root_id: str
    event_type: str = Field(..., description="FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_MOVED, FILE_RENAMED, etc.")
    is_directory: bool
    relative_path: str
    previous_relative_path: Optional[str] = None
    occurred_at: datetime
    collected_at: datetime
    processed_at: Optional[datetime] = None
    status: str = Field(..., description="pending, processed, ignored, failed")
    associated_file_id: Optional[str] = None
    sensitivity_label: Optional[str] = Field(None, description="RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC, or NOT_ASSESSED")
    file_type: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256_hash: Optional[str] = None
    event_source: str = "watchdog"
    error_category: Optional[str] = None


class PaginatedEventsResponse(BaseModel):
    """Paginated collection of filesystem activity events."""

    items: List[FileActivityEventItem]
    total: int
    page: int
    size: int
    pages: int


class MonitoringStatisticsResponse(BaseModel):
    """Aggregated activity event metrics and pipeline status."""

    total_events: int
    created_count: int
    modified_count: int
    deleted_count: int
    renamed_count: int
    processed_count: int
    ignored_count: int
    failed_count: int
    active_watchers_count: int
    queue_backlog: int
