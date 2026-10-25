"""Base Contract and Context for Network Detection Rules (Phase 7).

Defines abstract contracts for deterministic, explainable network threat detectors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.network import NetworkEvent


@dataclass
class NetworkEvaluationContext:
    """Bounded window telemetry context passed to network detection rules."""

    start_time: datetime
    end_time: datetime
    window_minutes: int
    db: Session
    events: List[NetworkEvent] = field(default_factory=list)
    connections: List[NetworkEvent] = field(default_factory=list)
    dns_events: List[NetworkEvent] = field(default_factory=list)
    ids_alerts: List[NetworkEvent] = field(default_factory=list)


@dataclass
class NetworkRuleMatch:
    """Outcome produced when a network detection rule fires."""

    rule_id: str
    rule_name: str
    rule_version: str
    score_contribution: int
    severity_impact: str  # LOW, MEDIUM, HIGH, CRITICAL
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_completeness: str = "COMPLETE"  # COMPLETE, PARTIAL, INSUFFICIENT
    relationship_type: str = "temporal"  # temporal, circumstantial, verified
    linked_event_ids: List[str] = field(default_factory=list)


class BaseNetworkRule(ABC):
    """Abstract base class for all SentinelDLP network detection rules."""

    rule_id: str
    name: str
    version: str = "1.0.0"
    description: str
    severity_impact: str
    score_contribution: int
    required_events: List[str]
    relationship_type: str = "temporal"

    @abstractmethod
    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        """Evaluate network telemetry within the bounded context."""
        pass
