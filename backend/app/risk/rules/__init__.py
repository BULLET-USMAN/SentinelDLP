"""Rules package for SentinelDLP Risk Engine (Phase 5).

Exports the 8 security detection rules and registry helper functions.
"""

from typing import List
from app.risk.rules.base import BaseDetectionRule
from app.risk.rules.bulk_operations import UnusualSensitiveFileActivityVolumeRule
from app.risk.rules.file_activity import RapidFileModificationRule
from app.risk.rules.monitoring_coverage import MonitoringCoverageFailureRule
from app.risk.rules.sensitive_deletion import SensitiveFileDeletionRule
from app.risk.rules.sensitive_files import SensitiveFileModificationRule
from app.risk.rules.suspicious_renames import BulkFileRenamingRule, FileExtensionChangeRule
from app.risk.rules.unusual_changes import RepeatedFileChangesRule
from app.risk.schemas import DetectionRuleCatalogItem


def get_default_rules() -> List[BaseDetectionRule]:
    """Instantiate and return the standard catalog of Phase 5 detection rules."""
    return [
        SensitiveFileModificationRule(),             # RULE 1: RULE-SENS-MOD
        RapidFileModificationRule(),                  # RULE 2: RULE-RAPID-MOD
        BulkFileRenamingRule(),                       # RULE 3: RULE-BULK-RENAME
        SensitiveFileDeletionRule(),                  # RULE 4: RULE-SENS-DEL
        RepeatedFileChangesRule(),                    # RULE 5: RULE-REPEAT-CHANGE
        UnusualSensitiveFileActivityVolumeRule(),      # RULE 6: RULE-SENS-VOLUME
        FileExtensionChangeRule(),                    # RULE 7: RULE-EXT-CHANGE
        MonitoringCoverageFailureRule(),              # RULE 8: RULE-COVERAGE-WARN
    ]


def get_rule_catalog() -> List[DetectionRuleCatalogItem]:
    """Return catalog metadata for all registered detection rules."""
    rules = get_default_rules()
    catalog: List[DetectionRuleCatalogItem] = []
    for r in rules:
        catalog.append(
            DetectionRuleCatalogItem(
                rule_id=r.rule_id,
                name=r.name,
                description=r.description,
                enabled=r.enabled,
                version=r.version,
                window_minutes=r.window_minutes,
                base_points=25 if r.window_minutes else 20,
                explanation_template=r.explanation_template,
            )
        )
    return catalog


__all__ = [
    "BaseDetectionRule",
    "SensitiveFileModificationRule",
    "RapidFileModificationRule",
    "BulkFileRenamingRule",
    "SensitiveFileDeletionRule",
    "RepeatedFileChangesRule",
    "UnusualSensitiveFileActivityVolumeRule",
    "FileExtensionChangeRule",
    "MonitoringCoverageFailureRule",
    "get_default_rules",
    "get_rule_catalog",
]
