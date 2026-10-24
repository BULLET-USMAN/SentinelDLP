"""Base Detection Rule Interface and Context Models for SentinelDLP (Phase 5).

Provides abstract contracts and data structures for implementing deterministic,
explainable security detection rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.severity import RiskSeverity


@dataclass
class TemporalContext:
    """Bounded historical aggregation metrics for the event's root and timeframe."""

    evaluation_time: datetime
    # 5-minute window
    distinct_modified_files_5m: int = 0
    recent_modified_paths_5m: List[str] = field(default_factory=list)
    distinct_renamed_files_5m: int = 0
    recent_renamed_paths_5m: List[str] = field(default_factory=list)
    changes_for_this_file_5m: int = 0
    # 15-minute window
    sensitive_deletions_15m: int = 0
    recent_deleted_sensitive_paths_15m: List[str] = field(default_factory=list)
    sensitive_events_count_15m: int = 0
    # Monitoring health
    queue_overflow_count: int = 0


@dataclass
class RuleEvaluationResult:
    """Result produced when a detection rule triggers."""

    rule_id: str
    rule_name: str
    rule_version: str
    score_contribution: int
    severity_impact: RiskSeverity
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    is_coverage_warning: bool = False


class BaseDetectionRule(ABC):
    """Abstract contract for detection rules."""

    rule_id: str
    name: str
    description: str
    version: str = "1.0.0"
    window_minutes: Optional[int] = None
    enabled: bool = True
    explanation_template: str = ""

    @abstractmethod
    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        """Evaluate the rule against the event and temporal context.

        Returns RuleEvaluationResult if triggered, or None if conditions not met.
        """
        pass
