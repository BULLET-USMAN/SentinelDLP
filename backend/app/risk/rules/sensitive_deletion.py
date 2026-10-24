"""RULE 4 — Sensitive File Deletion Activity (RULE-SENS-DEL).

Identifies multiple deletion events involving files with previously established
sensitive classifications (CONFIDENTIAL or RESTRICTED) within a 15-minute window.
Preserves historical classifications and provides explainable evidence for analysts to
differentiate authorized cleanup from potential data destruction or unauthorized tampering.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class SensitiveFileDeletionRule(BaseDetectionRule):
    """Detects multiple deletions of classified sensitive files."""

    rule_id = "RULE-SENS-DEL"
    name = "Sensitive File Deletion Activity"
    description = (
        "Identifies multiple deletion events involving files previously classified as "
        "CONFIDENTIAL or RESTRICTED within a 15-minute window."
    )
    version = "1.0.0"
    window_minutes = 15
    enabled = True
    explanation_template = (
        "Observed {count} deletion events of files classified as sensitive in the past 15 minutes. "
        "Deletion of sensitive assets requires operational verification."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Evaluates on file deletion events
        if event.is_directory or event.event_type != "FILE_DELETED":
            return None

        # Only triggers if this file was sensitive, or if sensitive deletions in window meet threshold
        is_current_sensitive = event.sensitivity_label in ("CONFIDENTIAL", "RESTRICTED")
        count = context.sensitive_deletions_15m

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        threshold = rule_config.get("threshold_deletions", 2)
        high_threshold = rule_config.get("high_threshold_deletions", 5)
        base_points = rule_config.get("base_points", 35)
        high_points = rule_config.get("high_points", 50)

        if count < threshold and not (is_current_sensitive and count >= 1):
            return None

        effective_count = max(count, 1 if is_current_sensitive else 0)
        if effective_count < threshold:
            return None

        if effective_count >= high_threshold:
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
            explanation=self.explanation_template.format(count=effective_count),
            evidence={
                "sensitive_deletions_count": effective_count,
                "window_minutes": self.window_minutes,
                "current_file": event.relative_path,
                "current_sensitivity": event.sensitivity_label,
                "sample_deleted_paths": context.recent_deleted_sensitive_paths_15m[:5],
            },
        )
