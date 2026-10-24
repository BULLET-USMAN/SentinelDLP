"""RULE 5 — Repeated File Changes (RULE-REPEAT-CHANGE).

Identifies patterns involving repeated modification, renaming, or recreation of the same file
across a short temporal window (5 minutes) after deduplication.
Repeated non-transient changes may indicate churn, lock-file collisions, rapid overwrite loops,
or progressive file alteration.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class RepeatedFileChangesRule(BaseDetectionRule):
    """Detects repeated modification or alteration of the same target file."""

    rule_id = "RULE-REPEAT-CHANGE"
    name = "Repeated File Changes"
    description = (
        "Identifies repeated creation, modification, or renaming operations affecting "
        "the same file path within a 5-minute window post-deduplication."
    )
    version = "1.0.0"
    window_minutes = 5
    enabled = True
    explanation_template = (
        "File '{filename}' underwent {count} separate operations in the past 5 minutes, "
        "indicating high-churn alteration."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        if event.is_directory:
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        threshold = rule_config.get("threshold_changes_single_file", 4)
        base_points = rule_config.get("base_points", 20)
        high_points = rule_config.get("high_points", 30)

        count = context.changes_for_this_file_5m
        if count < threshold:
            return None

        points = high_points if count >= (threshold * 2) else base_points
        impact = RiskSeverity.MEDIUM if points >= 30 else RiskSeverity.LOW
        filename = event.relative_path.split("/")[-1].split("\\")[-1]

        return RuleEvaluationResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=points,
            severity_impact=impact,
            explanation=self.explanation_template.format(filename=filename, count=count),
            evidence={
                "file_path": event.relative_path,
                "operation_count": count,
                "window_minutes": self.window_minutes,
                "current_event_type": event.event_type,
            },
        )
