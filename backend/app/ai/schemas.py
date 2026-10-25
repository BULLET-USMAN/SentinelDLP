"""Pydantic V2 Schemas for Phase 9: AI-Powered SOC Analyst & Security Investigation."""

from datetime import datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums and Value Types
# ---------------------------------------------------------------------------

ConfidenceAssessment = Literal[
    "STRONG_SUPPORT",
    "PARTIAL_SUPPORT",
    "LIMITED_SUPPORT",
    "INSUFFICIENT_EVIDENCE",
]

EvidenceCompleteness = Literal["COMPLETE", "PARTIAL", "INSUFFICIENT"]

AnalystReviewStatus = Literal["PENDING", "USEFUL", "INCORRECT", "NEEDS_REVIEW"]


# ---------------------------------------------------------------------------
# Findings & Evidence References
# ---------------------------------------------------------------------------

class ObservedFactItem(BaseModel):
    """Specific factual observation backed by an immutable system record ID."""

    fact: str = Field(description="Description of the factual observation")
    record_id: Optional[str] = Field(default=None, description="Database record ID supporting the fact")
    source_technology: str = Field(default="sentinel_core", description="Originating subsystem (e.g. watchdog, zeek)")
    provenance: str = Field(default="OBSERVED", description="Evidence provenance (OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED)")


class MitreAttackMappingItem(BaseModel):
    """Controlled MITRE ATT&CK mapping validated against local catalog."""

    technique_id: str = Field(description="MITRE ATT&CK Technique ID (e.g. T1074.001)")
    technique_name: str = Field(description="Official name of the technique")
    tactic: str = Field(description="Associated ATT&CK tactic (e.g. Collection, Exfiltration)")
    justification: str = Field(description="Explanation for why available evidence aligns with this technique")
    confidence: str = Field(default="PARTIAL_SUPPORT", description="Alignment strength based on verified records")


# ---------------------------------------------------------------------------
# Structured Investigation Report Schemas
# ---------------------------------------------------------------------------

class AIInvestigationReportResponse(BaseModel):
    """Full structured AI investigation report returned to the SOC analyst."""

    id: str
    investigation_id: Optional[str] = None
    alert_id: Optional[str] = None
    model_id: str
    provider_type: str
    status: str
    executive_summary: str
    assessment: str
    confidence_assessment: str
    evidence_completeness: str
    observed_facts: List[ObservedFactItem] = []
    possible_explanations: List[str] = []
    missing_evidence: List[str] = []
    recommended_actions: List[str] = []
    mitre_attack_mappings: List[MitreAttackMappingItem] = []
    evidence_references: List[str] = []
    tool_calls_count: int = 0
    prompt_template_version: str = "v1.0"
    report_schema_version: str = "v1.0"
    analyst_review_status: str = "PENDING"
    analyst_feedback_notes: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime
    execution_duration_ms: int = 0


class AnalyzeInvestigationRequest(BaseModel):
    """Request payload to trigger an automated AI security investigation."""

    analyst_query: Optional[str] = Field(
        default=None,
        description="Optional initial inquiry or hypothesis from the analyst",
    )
    force_refresh: bool = Field(
        default=False,
        description="Whether to generate a fresh report if an existing report is present",
    )


class AnalystFeedbackRequest(BaseModel):
    """Payload to record human analyst validation of an AI investigation report."""

    status: AnalystReviewStatus = Field(description="Review classification: USEFUL, INCORRECT, NEEDS_REVIEW")
    notes: Optional[str] = Field(default=None, description="Analyst review notes or justification")
    analyst_name: str = Field(default="soc_analyst", description="Identity of the reviewing analyst")


# ---------------------------------------------------------------------------
# Interactive Chat Schemas
# ---------------------------------------------------------------------------

class ChatMessageRequest(BaseModel):
    """Analyst prompt sent to the AI Security Assistant."""

    message: str = Field(min_length=1, max_length=2000, description="Security question or investigation instruction")
    session_id: Optional[str] = Field(default=None, description="Existing session ID to continue dialogue")
    investigation_id: Optional[str] = Field(default=None, description="Associated investigation ID for context")
    alert_id: Optional[str] = Field(default=None, description="Associated alert ID for context")
    analyst_name: str = Field(default="soc_analyst", description="Analyst identity")


class ChatMessageResponse(BaseModel):
    """Sanitized response from the AI Security Assistant."""

    message_id: str
    session_id: str
    role: str
    content: str
    evidence_references: List[str] = []
    tool_invocations: List[Dict[str, Any]] = []
    created_at: datetime


class ConversationSessionSummary(BaseModel):
    """Metadata summary of an AI conversation session."""

    id: str
    investigation_id: Optional[str] = None
    alert_id: Optional[str] = None
    title: str
    status: str
    model_id: str
    message_count: int = 0
    created_at: datetime
    updated_at: datetime


class ConversationSessionDetail(BaseModel):
    """Full conversation history for an investigation session."""

    id: str
    investigation_id: Optional[str] = None
    alert_id: Optional[str] = None
    title: str
    status: str
    model_id: str
    messages: List[ChatMessageResponse] = []
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# System Status & Model Schemas
# ---------------------------------------------------------------------------

class AIModelInfo(BaseModel):
    """Information regarding an available or target local AI model."""

    model_id: str
    provider: str
    download_size_approx: str
    vram_requirement_approx: str
    supports_tool_calling: bool
    supports_json_schema: bool
    is_active: bool
    description: str


class AIStatusResponse(BaseModel):
    """Observability status of the local AI subsystem."""

    provider_type: str
    model_id: str
    is_healthy: bool
    details: str
    active_features: List[str]
    safety_guardrails: List[str]
    model_storage_location: str
    available_models: List[AIModelInfo] = []
