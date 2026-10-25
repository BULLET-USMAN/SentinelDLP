"""Pydantic Schemas for SentinelDLP Centralized SOC Dashboard (Phase 8).

Defines schemas for:
- Aggregated security posture summary
- Risk severity distribution
- Unified security activity feed with provenance tagging
- Capability and sensor health status
- Analyst priority queue
- Global security metadata search
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecuritySummary(BaseModel):
    """High-level security summary metrics for executive SOC KPI tiles."""

    open_alerts_count: int = Field(..., description="Number of unresolved security alerts in OPEN status")
    high_critical_alerts_count: int = Field(..., description="Number of unresolved alerts with HIGH or CRITICAL severity")
    active_investigations_count: int = Field(..., description="Number of active exfiltration investigations")
    potential_exfiltrations_count: int = Field(..., description="Number of investigations flagged with confirmed or circumstantial exfil signals")
    sensitive_files_count: int = Field(..., description="Total files classified as CONFIDENTIAL or RESTRICTED")
    active_sensors_count: int = Field(..., description="Number of active, reporting telemetry sensors")
    visibility_gaps_count: int = Field(..., description="Number of sensors reporting visibility gaps or degraded states")


class RiskDistributionSummary(BaseModel):
    """Distribution of risk assessments across normalized severity bands."""

    low_count: int = Field(..., description="Assessments in LOW band (0-29)")
    medium_count: int = Field(..., description="Assessments in MEDIUM band (30-59)")
    high_count: int = Field(..., description="Assessments in HIGH band (60-79)")
    critical_count: int = Field(..., description="Assessments in CRITICAL band (80-100)")
    average_score: float = Field(..., description="Average risk score across all assessments")
    total_assessments: int = Field(..., description="Total risk evaluations performed")
    explanation: str = Field(
        default="File sensitivity provides data context, not proof of malicious activity. Risk scores incorporate access velocity, bulk modification, archive staging, and transfer telemetry.",
        description="Core risk scoring architectural philosophy",
    )


class RecentActivityItem(BaseModel):
    """Unified security event feed item combining file, alert, exfil, and network telemetry."""

    id: str
    timestamp: datetime
    category: str = Field(..., description="Event category: FILE_ACTIVITY, SECURITY_ALERT, RISK_ASSESSMENT, EXFILTRATION, NETWORK_IDS, DNS_ANOMALY")
    title: str
    description: str
    severity: Optional[str] = Field(None, description="LOW, MEDIUM, HIGH, CRITICAL if applicable")
    source_technology: str = Field(..., description="watchdog, zeek, suricata, pcap_analyzer, correlation_engine, risk_engine")
    evidence_provenance: str = Field(..., description="OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED")
    reference_id: Optional[str] = None


class RiskTrendPoint(BaseModel):
    """Time-series risk assessment frequency data point."""

    bucket: str = Field(..., description="Date or hour timestamp bucket")
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    total: int = 0


class CapabilityHealth(BaseModel):
    """Status and observability of an individual SentinelDLP platform module."""

    component_id: str
    name: str
    status: str = Field(..., description="HEALTHY, DEGRADED, UNAVAILABLE, NOT_CONFIGURED, UNKNOWN")
    details: str
    telemetry_freshness: str = Field(default="FRESH", description="FRESH, STALE, or UNAVAILABLE")
    last_active: Optional[datetime] = None


class PriorityQueueItem(BaseModel):
    """High-priority unresolved alert or investigation awaiting analyst triage."""

    id: str
    item_type: str = Field(..., description="ALERT or INVESTIGATION")
    title: str
    severity: str
    risk_score: Optional[int] = None
    status: str
    timestamp: datetime
    rule_name: Optional[str] = None
    analyst: Optional[str] = None
    reference_url: Optional[str] = None


class DashboardOverviewResponse(BaseModel):
    """Comprehensive SOC Dashboard Overview Aggregation Payload."""

    security_summary: SecuritySummary
    risk_distribution: RiskDistributionSummary
    recent_activity: List[RecentActivityItem]
    risk_trends: List[RiskTrendPoint]
    monitoring_status: List[CapabilityHealth]
    priority_queue: List[PriorityQueueItem]
    data_freshness_timestamp: datetime
    coverage_completeness: str = Field(
        default="CONTAINER_BOUNDED_LOCAL_MONITORING",
        description="Transparency indicator indicating defensive coverage boundary",
    )


class SearchResultItem(BaseModel):
    """Single match item returned from global SOC search."""

    result_type: str = Field(..., description="ALERT, INVESTIGATION, FILE, RULE, INDICATOR")
    id: str
    title: str
    subtitle: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    link_tab: str = Field(..., description="UI tab navigation target: alerts, investigations, scanner, detection, network, risk")
    link_id: Optional[str] = None


class DashboardSearchResponse(BaseModel):
    """Global search response payload."""

    query: str
    total_results: int
    results: List[SearchResultItem]
