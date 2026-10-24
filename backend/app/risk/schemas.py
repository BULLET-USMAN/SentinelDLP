"""Pydantic schemas for SentinelDLP Risk Engine & Alerts (Phase 5).

Defines serialization, validation, and request/response models for:
- Risk assessments & rule matches
- Security alerts & triage lifecycle
- Analyst audit logs
- Aggregated telemetry & statistics
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.risk.severity import AlertStatus, DetectionConfidence, EvidenceCompleteness, RiskSeverity


class RuleMatchItem(BaseModel):
    """Granular rule match item contributing to an assessment."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    rule_id: str
    rule_name: str
    rule_version: str = "1.0.0"
    score_contribution: int = 0
    severity_impact: RiskSeverity = RiskSeverity.LOW
    match_timestamp: datetime
    evidence_data: Optional[Dict[str, Any]] = None


class RiskAssessmentItem(BaseModel):
    """Complete explainable risk assessment for a security event."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    root_id: str
    associated_file_id: Optional[str] = None
    risk_score: int = Field(ge=0, le=100)
    severity: RiskSeverity
    evidence_completeness: EvidenceCompleteness
    detection_confidence: DetectionConfidence
    scoring_policy_version: str
    assessment_status: str
    explanation: str
    limitations: Optional[str] = None
    recommended_action: Optional[str] = None
    assessed_at: datetime
    rule_matches: List[RuleMatchItem] = []
    alert_id: Optional[str] = None


class AlertAuditLogItem(BaseModel):
    """Immutable record of an analyst action or alert status transition."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    previous_status: str
    new_status: str
    action: str
    analyst_notes: Optional[str] = None
    performed_by: str = "security_analyst"
    performed_at: datetime


class SecurityAlertItem(BaseModel):
    """Summary item for security alerts."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    root_id: str
    title: str
    description: str
    severity: RiskSeverity
    risk_score: int
    status: AlertStatus
    deduplication_key: str
    repeat_count: int = 1
    recommended_action: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class SecurityAlertDetail(SecurityAlertItem):
    """Detailed alert item including assessment and audit trail."""

    assessment: Optional[RiskAssessmentItem] = None
    audit_logs: List[AlertAuditLogItem] = []


class UpdateAlertStatusRequest(BaseModel):
    """Analyst request to triage or update an alert's lifecycle status."""

    status: AlertStatus
    analyst_notes: Optional[str] = Field(None, max_length=1000)
    performed_by: Optional[str] = Field("security_analyst", max_length=64)


class PaginatedRiskAssessmentsResponse(BaseModel):
    """Paginated list of risk assessments."""

    items: List[RiskAssessmentItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class PaginatedSecurityAlertsResponse(BaseModel):
    """Paginated list of security alerts."""

    items: List[SecurityAlertItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class RiskStatisticsResponse(BaseModel):
    """Aggregated risk intelligence telemetry."""

    total_assessments: int
    low_count: int
    medium_count: int
    high_count: int
    critical_count: int
    average_score: float
    score_distribution: Dict[str, int]  # "0-29", "30-59", "60-79", "80-100"


class AlertStatisticsResponse(BaseModel):
    """Aggregated alert status metrics."""

    total_alerts: int
    open_count: int
    acknowledged_count: int
    investigating_count: int
    resolved_count: int
    false_positive_count: int
    by_severity: Dict[str, int]  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


class DetectionRuleCatalogItem(BaseModel):
    """Rule catalog metadata for rule inspection."""

    rule_id: str
    name: str
    description: str
    enabled: bool
    version: str
    window_minutes: Optional[int] = None
    base_points: int
    explanation_template: str
