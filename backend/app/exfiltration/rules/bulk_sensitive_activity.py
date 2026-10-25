"""EXFIL-001: High-Volume Sensitive File Activity (Phase 6).

Detects a high rate of sensitive file operations (access, modification, reads)
occurring within a bounded correlation window.
"""

from typing import Any, Dict, List, Optional
from app.exfiltration.policies import THRESHOLD_HIGH_VOLUME_SENSITIVE_COUNT
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceProvenance,
    RelationshipType,
)
from app.exfiltration.rules.base import (
    BaseExfiltrationRule,
    ExfiltrationContext,
    ExfiltrationRuleMatch,
)
from app.risk.severity import RiskSeverity


class HighVolumeSensitiveActivityRule(BaseExfiltrationRule):
    """EXFIL-001: Triggers when sensitive file activities exceed volume threshold in window."""

    rule_id = "EXFIL-001"
    name = "High-Volume Sensitive File Activity"
    version = "1.0.0"
    description = "Detects rapid succession of sensitive file operations within the correlation window."
    score_contribution = 25
    severity_impact = RiskSeverity.MEDIUM
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        sensitive_count = len(context.sensitive_file_events)
        if sensitive_count < THRESHOLD_HIGH_VOLUME_SENSITIVE_COUNT:
            return None

        # Build evidence links
        linked_evidence: List[Dict[str, Any]] = []
        unique_paths = set()
        for evt in context.sensitive_file_events[:10]:
            unique_paths.add(evt.file_path)
            linked_evidence.append({
                "evidence_type": "file_activity",
                "evidence_id": str(evt.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": evt.timestamp,
                "description": f"Sensitive file {evt.activity_type.lower()}: {evt.file_path}",
            })

        summary = (
            f"Observed {sensitive_count} sensitive file operations across {len(unique_paths)} "
            f"distinct files in {context.window_minutes}m window."
        )

        return ExfiltrationRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            relationship_type=self.relationship_type,
            evidence_completeness=EvidenceCompleteness.PARTIAL,
            summary=summary,
            details={
                "sensitive_event_count": sensitive_count,
                "threshold": THRESHOLD_HIGH_VOLUME_SENSITIVE_COUNT,
                "distinct_file_count": len(unique_paths),
                "sample_paths": list(unique_paths)[:5],
            },
            linked_evidence=linked_evidence,
        )
