"""RULE 3 — Bulk File Renaming (RULE-BULK-RENAME) &
RULE 7 — File Extension Change (RULE-EXT-CHANGE).

Detects anomalous rename activity:
- High volume of distinct files renamed in a short window.
- Alteration of file extensions (with extra telemetry if extension is known suspicious).
Strictly adheres to defensive security ethics: bulk renaming or extension changes alone
do NOT establish ransomware or malicious intent; findings are described accurately as
unusual filesystem behaviors requiring SOC review.
"""

from pathlib import Path
from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext
from app.risk.severity import RiskSeverity


class BulkFileRenamingRule(BaseDetectionRule):
    """Detects rapid volume of file renaming operations."""

    rule_id = "RULE-BULK-RENAME"
    name = "Bulk File Renaming"
    description = (
        "Detects an unusually high number of distinct files being renamed within a short period. "
        "Flags potential bulk transformations or mass renaming activity for analyst review."
    )
    version = "1.0.0"
    window_minutes = 5
    enabled = True
    explanation_template = (
        "Observed {count} distinct file rename operations in the past 5 minutes. "
        "Bulk renaming indicates mass structural alteration."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        # Evaluates on file rename / move events
        if event.is_directory or event.event_type not in ("FILE_RENAMED", "FILE_MOVED"):
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        threshold = rule_config.get("threshold_renames", 5)
        high_threshold = rule_config.get("high_threshold_renames", 12)
        base_points = rule_config.get("base_points", 30)
        high_points = rule_config.get("high_points", 45)

        count = context.distinct_renamed_files_5m
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
                "distinct_renamed_files_count": count,
                "window_minutes": self.window_minutes,
                "sample_renamed_paths": context.recent_renamed_paths_5m[:5],
                "trigger_file": event.relative_path,
                "previous_path": event.previous_relative_path,
            },
        )


class FileExtensionChangeRule(BaseDetectionRule):
    """Detects modification of a file's extension during renaming."""

    rule_id = "RULE-EXT-CHANGE"
    name = "File Extension Change"
    description = (
        "Identifies files whose extensions were altered during a rename or move operation. "
        "Records the prior and new extensions as context for SOC analysts."
    )
    version = "1.0.0"
    window_minutes = None
    enabled = True
    explanation_template = (
        "File extension modified from '{old_ext}' to '{new_ext}' ({filename})."
    )

    def evaluate(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: Dict[str, Any],
    ) -> Optional[RuleEvaluationResult]:
        if not self.enabled:
            return None

        if event.is_directory or event.event_type not in ("FILE_RENAMED", "FILE_MOVED"):
            return None

        if not event.previous_relative_path:
            return None

        old_ext = Path(event.previous_relative_path).suffix.lower()
        new_ext = Path(event.relative_path).suffix.lower()

        if not old_ext or not new_ext or old_ext == new_ext:
            return None

        rule_config = policy.get("rules", {}).get(self.rule_id, {})
        base_points = rule_config.get("base_points", 20)
        suspicious_exts = set(rule_config.get("suspicious_extensions", []))
        bonus = rule_config.get("suspicious_extension_bonus", 25)
        multiplier = rule_config.get("sensitive_multiplier", 1.5)

        points = base_points
        is_suspicious_ext = new_ext in suspicious_exts
        if is_suspicious_ext:
            points += bonus

        # Check sensitivity context
        if event.sensitivity_label in ("CONFIDENTIAL", "RESTRICTED"):
            points = int(points * multiplier)

        filename = Path(event.relative_path).name

        return RuleEvaluationResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=points,
            severity_impact=RiskSeverity.MEDIUM if points >= 30 else RiskSeverity.LOW,
            explanation=self.explanation_template.format(
                old_ext=old_ext,
                new_ext=new_ext,
                filename=filename,
            ),
            evidence={
                "previous_extension": old_ext,
                "new_extension": new_ext,
                "is_suspicious_extension": is_suspicious_ext,
                "previous_relative_path": event.previous_relative_path,
                "new_relative_path": event.relative_path,
                "sensitivity_label": event.sensitivity_label,
            },
        )
