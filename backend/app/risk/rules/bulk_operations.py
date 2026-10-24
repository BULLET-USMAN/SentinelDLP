"""RULE 6 — Unusual Sensitive File Activity Volume (RULE-SENS-VOLUME).

Detects an unusual number of observable filesystem changes affecting classified sensitive files
(CONFIDENTIAL or RESTRICTED) across a 15-minute window.
Adheres strictly to telemetry boundaries: Filesystem events observe file modifications and moves;
they do NOT confirm file reads, memory access, or network exfiltration.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class UnusualSensitiveFileActivityVolumeRule(BaseDetectionRule):
    """Detects elevated volume of activity on sensitive files."""

    rule_id = "RULE-SENS-VOLUME"
    name = "Unusual Sensitive File Activity Volume"
    description = (
        "Detects an unusually high volume of observable filesystem operations affecting "
        "files classified as CONFIDENTIAL or RESTRICTED across a 15-minute window."
    )
    version = "1.0.0"
    window_minutes = 15
    enabled = True
    explanation_template = (
        "Observed {count} operations on sensitive files within the past 15 minutes, "
        "indicating concentrated activity on confidential corporate assets."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Triggers if the current event affects a sensitive file and window volume meets threshold
        if event.is_directory or event.sensitivity_label not in ("CONFIDENTIAL", "RESTRICTED"):
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        threshold = rule_config.get("threshold_sensitive_events", 5)
        high_threshold = rule_config.get("high_threshold_sensitive_events", 10)
        base_points = rule_config.get("base_points", 30)
        high_points = rule_config.get("high_points", 45)

        count = context.sensitive_events_count_15m
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
                "sensitive_events_count": count,
                "window_minutes": self.window_minutes,
                "current_file": event.relative_path,
                "current_sensitivity": event.sensitivity_label,
            },
        )
