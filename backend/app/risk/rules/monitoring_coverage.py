"""RULE 8 — Monitoring Coverage Failure (RULE-COVERAGE-WARN).

Identifies periods of degraded, interrupted, or saturated monitoring (e.g., event queue overflows,
unreadable files, or dropped OS notifications).
Strictly treated as a telemetry quality and visibility warning rather than a confirmed security threat.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class MonitoringCoverageFailureRule(BaseDetectionRule):
    """Detects telemetry degradation or coverage gaps."""

    rule_id = "RULE-COVERAGE-WARN"
    name = "Monitoring Coverage Failure"
    description = (
        "Identifies periods of missing, interrupted, or degraded monitoring telemetry, "
        "such as queue overflows or dropped notification buffers. Emits a diagnostic coverage warning."
    )
    version = "1.0.0"
    window_minutes = None
    enabled = True
    explanation_template = (
        "Telemetry coverage warning: {reason}. Security visibility may be incomplete."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Check if event had an error or context shows queue overflows
        reason = None
        if event.error_category == "queue_overflow":
            reason = "Event queue experienced overflow; burst filesystem events were dropped"
        elif event.error_category == "observer_error":
            reason = "Filesystem observer reported an internal capture error"
        elif context.queue_overflow_count > 0:
            reason = f"Monitoring session has recorded {context.queue_overflow_count} dropped events"

        if not reason:
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        base_points = rule_config.get("base_points", 10)

        return RuleEvaluationResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=base_points,
            severity_impact=RiskSeverity.LOW,
            explanation=self.explanation_template.format(reason=reason),
            evidence={
                "reason": reason,
                "error_category": event.error_category,
                "session_overflow_count": context.queue_overflow_count,
            },
            is_coverage_warning=True,
        )
