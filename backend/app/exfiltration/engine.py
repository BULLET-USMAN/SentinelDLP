"""Exfiltration Engine Facade for SentinelDLP (Phase 6).

Coordinates rules, bounded correlation passes, and timeline generation.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from app.exfiltration.correlator import ExfiltrationCorrelator
from app.exfiltration.rules import get_all_exfiltration_rules
from app.exfiltration.schemas import ExfiltrationRuleDefinitionResponse
from app.models.exfiltration import ExfiltrationInvestigation


class ExfiltrationEngine:
    """Facade for exfiltration detection rules, correlation runs, and telemetry processing."""

    @staticmethod
    def get_registered_rules() -> List[ExfiltrationRuleDefinitionResponse]:
        """Return list of all registered detection rules with metadata."""
        definitions = []
        for rule in get_all_exfiltration_rules():
            definitions.append(
                ExfiltrationRuleDefinitionResponse(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    version=rule.version,
                    description=rule.description,
                    score_contribution=rule.score_contribution,
                    severity_impact=rule.severity_impact.value,
                    required_signals=["file_activity", "transfer_event"],
                    relationship_type=rule.relationship_type.value,
                )
            )
        return definitions

    @staticmethod
    def execute_correlation(
        db: Session,
        window_minutes: int = 15,
        endpoint_id: Optional[str] = "endpoint-alpha-01",
    ) -> List[ExfiltrationInvestigation]:
        """Run temporal correlation across the specified window."""
        correlator = ExfiltrationCorrelator(db)
        return correlator.run_correlation(window_minutes=window_minutes, endpoint_id=endpoint_id)


# Global Engine Instance
exfiltration_engine = ExfiltrationEngine()
