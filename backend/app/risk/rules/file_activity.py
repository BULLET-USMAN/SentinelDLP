"""RULE 2 — Rapid File Modification Activity (RULE-RAPID-MOD).

Detects unusually frequent file modifications across multiple distinct files within a short
temporal window (e.g., 5 minutes). High modification velocity across distinct files may indicate
automated batch scripts, rapid tampering, or bulk transformation processes.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class RapidFileModificationRule(BaseDetectionRule):
    """Detects rapid modification velocity across distinct files."""

    rule_id = "RULE-RAPID-MOD"
    name = "Rapid File Modification Activity"
    description = (
        "Detects an elevated number of distinct files modified within a 5-minute window. "
        "Differentiates burst script activity from ordinary single-file editing."
    )
    version = "1.0.0"
    window_minutes = 5
    enabled = True
    explanation_template = (
        "Observed {count} distinct files modified within the past 5 minutes, exceeding the baseline threshold."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Evaluates on file modification events
        if event.is_directory or event.event_type != "FILE_MODIFIED":
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        threshold = rule_config.get("threshold_files", 5)
        high_threshold = rule_config.get("high_threshold_files", 15)
        base_points = rule_config.get("base_points", 25)
        high_points = rule_config.get("high_points", 40)

        count = context.distinct_modified_files_5m
        if count < threshold:
            return None

        if count >= high_threshold:
            points = high_points
            impact = RiskSeverity.HIGH
        else:
            points = base_points
            impact = RiskSeverity.MEDIUM

        return RuleEvaluationResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=points,
            severity_impact=impact,
            explanation=self.explanation_template.format(count=count),
            evidence={
                "distinct_modified_files_count": count,
                "window_minutes": self.window_minutes,
                "sample_paths": context.recent_modified_paths_5m[:5],
                "trigger_file": event.relative_path,
            },
        )
