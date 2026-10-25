"""Pydantic schemas for Exfiltration Detection and Event Correlation (Phase 6).

Strictly isolates sensitive data: payloads and secret values are never accepted or emitted.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceConfidence,
    EvidenceProvenance,
    InvestigationStatus,
    RelationshipType,
)
from app.risk.severity import RiskSeverity


class TransferEventCreate(BaseModel):
    """Payload to record an outbound data transfer event (e.g. from lab harness)."""
    source_endpoint_id: str = Field(default="endpoint-alpha-01", max_length=64)
    occurred_at: datetime
    direction: str = Field(default="OUTBOUND", max_length=16)
    destination_category: str = Field(default="UNKNOWN", max_length=32)
    destination_host: str = Field(..., max_length=255)
    protocol: str = Field(default="HTTPS", max_length=16)
    byte_count: int = Field(..., ge=0)
    verified_file_reference: Optional[str] = Field(default=None, max_length=255)
    trusted_process_reference: Optional[str] = Field(default=None, max_length=255)
    evidence_source: str = Field(default="LAB_SYNTHETIC_HARNESS", max_length=64)
    evidence_provenance: EvidenceProvenance = Field(default=EvidenceProvenance.LAB_SIMULATED)
    is_simulated: bool = Field(default=True)
    context_data: Optional[str] = None


class TransferEventResponse(BaseModel):
    """Structured response for a transfer event."""
    id: str
    source_endpoint_id: str
    occurred_at: datetime
    collected_at: datetime
    direction: str
    destination_category: str
    destination_host: str
    protocol: str
    byte_count: int
    verified_file_reference: Optional[str]
    trusted_process_reference: Optional[str]
    evidence_source: str
    evidence_provenance: str
    is_simulated: bool
    status: str
    context_data: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class TransferEventBatchImport(BaseModel):
    """Batch import of synthetic or external transfer telemetry."""
    events: List[TransferEventCreate]


class CorrelationRecordResponse(BaseModel):
    """Match details for an individual exfiltration rule."""
    id: str
    rule_id: str
    rule_name: str
    rule_version: str
    score_contribution: int
    relationship_type: str
    evidence_completeness: str
    matched_at: datetime
    summary: str
    details_json: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class InvestigationEvidenceLinkResponse(BaseModel):
    """Correlated forensic evidence link."""
    id: str
    evidence_type: str
    evidence_id: str
    evidence_provenance: str
    relationship_nature: str
    timestamp: datetime
    description: str
    metadata_json: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ExfiltrationTimelineItem(BaseModel):
    """Chronologically sorted investigation timeline item."""
    id: str
    timestamp: datetime
    title: str
    description: str
    category: str  # FILE_ACTIVITY, ARCHIVE_EVENT, OUTBOUND_TRANSFER, RISK_ALERT, CORRELATION_RULE
    evidence_provenance: str  # OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED
    relationship_type: str  # temporal, circumstantial, verified
    severity: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExfiltrationInvestigationResponse(BaseModel):
    """Summary item for investigations table."""
    id: str
    title: str
    description: str
    status: InvestigationStatus
    risk_score: int
    severity: RiskSeverity
    evidence_confidence: EvidenceConfidence
    evidence_completeness: EvidenceCompleteness
    primary_endpoint_id: Optional[str]
    correlation_window_minutes: int
    rules_triggered_count: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    assigned_analyst: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class ExfiltrationInvestigationDetailResponse(ExfiltrationInvestigationResponse):
    """Detailed view including rule matches, evidence links, and notes."""
    investigation_notes: Optional[str] = None
    correlation_records: List[CorrelationRecordResponse] = []
    evidence_links: List[InvestigationEvidenceLinkResponse] = []


class InvestigationStatusUpdate(BaseModel):
    """Analyst triage update for an investigation."""
    status: InvestigationStatus
    assigned_analyst: Optional[str] = None
    notes: Optional[str] = None


class ExfiltrationRuleDefinitionResponse(BaseModel):
    """Metadata schema describing a registered detection rule."""
    rule_id: str
    name: str
    version: str
    description: str
    score_contribution: int
    severity_impact: str
    required_signals: List[str]
    relationship_type: str


class ExfiltrationCorrelateRequest(BaseModel):
    """Trigger manual or scoped correlation run."""
    window_minutes: int = Field(default=15, ge=1, le=120)
    endpoint_id: Optional[str] = None


class ExfiltrationCorrelateResponse(BaseModel):
    """Summary result of a correlation engine pass."""
    investigations_created: int
    rules_evaluated: int
    transfer_events_analyzed: int
    file_events_analyzed: int
    window_minutes: int
    timestamp: datetime


class ExfiltrationStatisticsResponse(BaseModel):
    """KPI summary cards for exfiltration monitoring dashboard."""
    total_investigations: int
    open_investigations: int
    critical_investigations: int
    high_investigations: int
    simulated_transfer_count: int
    rules_active_count: int
    average_risk_score: float
