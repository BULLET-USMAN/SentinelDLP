"""Pydantic Schemas for Sensitive Data Detection & Classification (Phase 3).

Strictly typed API schemas for findings, classifications, and summaries.
Enforces zero disclosure of raw file content or sensitive secret values.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class DetectionRuleInfo(BaseModel):
    """Metadata regarding an active detection rule."""

    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule title")
    category: str = Field(..., description="Category (PII, CREDENTIALS, FINANCIAL, DOCUMENT_LABELS)")
    confidence: str = Field(..., description="Default confidence tier (LOW, MEDIUM, HIGH)")
    suggested_classification: str = Field(..., description="Default sensitivity level mapped to rule")
    description: str = Field(..., description="Security explanation and detection criteria")


class FindingItem(BaseModel):
    """Sanitized finding item without sensitive substring content."""

    id: str = Field(..., description="Unique finding UUID")
    scanned_file_id: str = Field(..., description="Associated scanned file identifier")
    rule_id: str = Field(..., description="Matched detection rule identifier")
    rule_version: str = Field("1.0.0", description="Rule catalog version")
    category: str = Field(..., description="Finding category")
    confidence: str = Field(..., description="Confidence rating")
    occurrence_count: int = Field(1, description="Number of pattern matches within the file")
    detected_at: datetime = Field(..., description="Timestamp when finding was recorded")


class PaginatedFindingsResponse(BaseModel):
    """Paginated collection of detection findings."""

    items: List[FindingItem]
    total: int
    page: int
    size: int
    pages: int


class FileClassificationItem(BaseModel):
    """Sensitivity classification metadata for a scanned file."""

    id: str = Field(..., description="Classification record identifier")
    scanned_file_id: str = Field(..., description="Scanned file identifier")
    sensitivity_label: str = Field(..., description="RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC, or NOT_ASSESSED")
    policy_version: str = Field(..., description="Classification policy baseline version")
    inspection_status: str = Field(..., description="Status of extraction (inspected, partial, unsupported, etc.)")
    explanation: str = Field(..., description="Auditable reasoning for assigned classification")
    highest_confidence: str = Field(..., description="Highest confidence level of triggering findings")
    classified_at: datetime = Field(..., description="Classification evaluation timestamp")


class ClassifiedFileOverviewItem(BaseModel):
    """Overview item combining file inventory details with its classification."""

    file_id: str
    scan_job_id: str
    filename: str
    relative_path: str
    file_extension: str
    detected_type: str
    size_bytes: int
    sensitivity_label: str
    highest_confidence: str
    inspection_status: str
    findings_count: int
    scan_timestamp: datetime


class PaginatedClassifiedFilesResponse(BaseModel):
    """Paginated collection of classified files."""

    items: List[ClassifiedFileOverviewItem]
    total: int
    page: int
    size: int
    pages: int


class FileClassificationDetail(BaseModel):
    """Comprehensive zero-leakage classification report for an individual file."""

    file_id: str
    filename: str
    relative_path: str
    detected_type: str
    size_bytes: int
    sha256_hash: Optional[str]
    classification: FileClassificationItem
    findings: List[FindingItem]


class SensitivitySummaryResponse(BaseModel):
    """Aggregated detection and classification metrics for a scan job."""

    scan_job_id: str
    files_inspected: int
    sensitive_files_count: int
    public_count: int
    internal_count: int
    confidential_count: int
    restricted_count: int
    not_assessed_count: int
    pii_count: int
    credential_count: int
    financial_count: int
    confidential_label_count: int
    created_at: datetime
