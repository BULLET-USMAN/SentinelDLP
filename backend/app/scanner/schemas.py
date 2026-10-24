"""Pydantic Schemas for Scanner Engine & Inventory API (Phase 2)."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class AuthorizedRootInfo(BaseModel):
    """Schema representing an administrator-approved scan root."""

    root_id: str = Field(..., description="Unique machine-readable identifier")
    name: str = Field(..., description="Human-readable root name")
    path: str = Field(..., description="Sanitized directory path")
    description: str = Field(..., description="Scope of contained files")


class ScanCreateRequest(BaseModel):
    """Schema for initiating a new scan job."""

    root_id: str = Field(..., description="Target authorized scan root identifier")


class ScanJobSummary(BaseModel):
    """Schema for scan job status and aggregated execution metrics."""

    id: str = Field(..., description="Unique Scan Job UUID")
    root_id: str = Field(..., description="Target root identifier")
    root_path: str = Field(..., description="Target root filesystem path")
    status: str = Field(..., description="Scan state: pending, running, completed, failed, or cancelled")
    started_at: datetime = Field(..., description="UTC start timestamp")
    completed_at: Optional[datetime] = Field(None, description="UTC completion timestamp")

    files_discovered: int = Field(0, description="Total files discovered during traversal")
    files_processed: int = Field(0, description="Total files successfully scanned and hashed")
    files_skipped: int = Field(0, description="Total files skipped due to policy or size limits")
    error_count: int = Field(0, description="Total files or directories encountering errors")
    total_bytes_processed: int = Field(0, description="Aggregate volume processed in bytes")
    duration_seconds: Optional[float] = Field(None, description="Elapsed execution duration in seconds")
    error_message: Optional[str] = Field(None, description="Failure description if failed")


class ScannedFileItem(BaseModel):
    """Schema for an individual file inventory record."""

    id: str = Field(..., description="Unique file record UUID")
    scan_job_id: str = Field(..., description="Parent Scan Job UUID")
    filename: str = Field(..., description="File name with extension")
    relative_path: str = Field(..., description="Path relative to scan root")
    file_extension: str = Field(..., description="Normalized file extension")
    detected_type: str = Field(..., description="Classified file type description")
    size_bytes: int = Field(..., description="File size in bytes")
    created_at: Optional[datetime] = Field(None, description="File creation timestamp")
    modified_at: Optional[datetime] = Field(None, description="Last modification timestamp")
    sha256_hash: Optional[str] = Field(None, description="Cryptographic SHA-256 digest")
    scan_timestamp: datetime = Field(..., description="UTC timestamp of inspection")
    status: str = Field(..., description="Inspection outcome: scanned, skipped, or error")
    error_message: Optional[str] = Field(None, description="Error explanation if status != scanned")
    type_mismatch: bool = Field(False, description="Flag indicating extension differs from signature")


class PaginatedFilesResponse(BaseModel):
    """Schema for paginated file inventory results."""

    items: List[ScannedFileItem] = Field(default_factory=list)
    total: int = Field(..., description="Total records matching query")
    page: int = Field(..., description="Current page number (1-indexed)")
    size: int = Field(..., description="Page size limit")
    pages: int = Field(..., description="Total pages available")


class ScanCancellationResponse(BaseModel):
    """Schema for scan cancellation request response."""

    scan_id: str
    status: str
    message: str
