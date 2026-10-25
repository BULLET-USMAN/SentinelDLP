"""Base Exfiltration Detection Rule Interface and Context (Phase 6).

Defines the contract for exfiltration correlation detection rules.
Enforces deterministic scoring, explicit relationship typing, and forensic metadata.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceProvenance,
    RelationshipType,
)
from app.models.monitoring import FileActivityEvent
from app.models.risk import RiskAssessment
from app.models.exfiltration import TransferEvent
from app.risk.severity import RiskSeverity


@dataclass
class ExfiltrationContext:
    """Bounded temporal context of telemetry collected within a correlation window."""

    start_time: datetime
    end_time: datetime
    window_minutes: int
    endpoint_id: Optional[str]
    file_events: List[FileActivityEvent] = field(default_factory=list)
    transfer_events: List[TransferEvent] = field(default_factory=list)
    risk_assessments: List[RiskAssessment] = field(default_factory=list)
    archive_events: List[FileActivityEvent] = field(default_factory=list)
    sensitive_file_events: List[FileActivityEvent] = field(default_factory=list)


@dataclass
class ExfiltrationRuleMatch:
    """Outcome produced when an exfiltration rule detects a correlated pattern."""

    rule_id: str
    rule_name: str
    rule_version: str
    score_contribution: int
    severity_impact: RiskSeverity
    relationship_type: RelationshipType
    evidence_completeness: EvidenceCompleteness
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    linked_evidence: List[Dict[str, Any]] = field(default_factory=list)


class BaseExfiltrationRule(ABC):
    """Abstract base class for all SentinelDLP exfiltration detection rules."""

    rule_id: str
    name: str
    version: str = "1.0.0"
    description: str
    score_contribution: int
    severity_impact: RiskSeverity
    relationship_type: RelationshipType = RelationshipType.TEMPORAL

    @abstractmethod
    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        """Evaluate the bounded context and return an ExfiltrationRuleMatch if conditions are satisfied."""
        pass
