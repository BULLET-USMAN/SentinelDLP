"""RULE 1 — Sensitive File Modification (RULE-SENS-MOD).

Identifies file modification events involving files classified as CONFIDENTIAL or RESTRICTED.
Adheres to the core philosophy: File sensitivity is context, not proof of malicious activity.
An ordinary modification on a sensitive file receives a modest score and remains in the LOW
severity band unless combined with abnormal velocity, volume, or structural changes.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class SensitiveFileModificationRule(BaseDetectionRule):
    """Detects modification of sensitive files."""

    rule_id = "RULE-SENS-MOD"
    name = "Sensitive File Modification"
    description = (
        "Identifies modification events involving files classified as CONFIDENTIAL or RESTRICTED. "
        "Provides foundational sensitivity context without declaring malicious behavior."
    )
    version = "1.0.0"
    window_minutes = None
    enabled = True
    explanation_template = "File classified as {label} was modified ({filename})."

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Must be a file modification
        if event.is_directory or event.event_type != "FILE_MODIFIED":
            return None

        label = event.sensitivity_label
        if not label or label in ("PUBLIC", "NOT_ASSESSED", "INTERNAL"):
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        weights = rule_config.get("weights", {"RESTRICTED": 25, "CONFIDENTIAL": 15})
        points = weights.get(label, 0)
        if points <= 0:
            return None

        filename = event.relative_path.split("/")[-1].split("\\")[-1]

        return RuleEvaluationResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=points,
            severity_impact=RiskSeverity.LOW,
            explanation=self.explanation_template.format(label=label, filename=filename),
            evidence={
                "sensitivity_label": label,
                "file_path": event.relative_path,
                "event_type": event.event_type,
                "sha256_hash": event.sha256_hash,
                "size_bytes": event.size_bytes,
            },
        )
