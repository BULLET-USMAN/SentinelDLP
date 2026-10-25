"""EXFIL-005: Unfamiliar Destination Transfer (Phase 6).

Detects outbound transfer events to unapproved or untrusted external endpoints
outside the organization's approved baseline allowlist.
"""

from typing import Any, Dict, List, Optional
from app.exfiltration.policies import is_destination_approved
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


class UnfamiliarDestinationRule(BaseExfiltrationRule):
    """EXFIL-005: Detects outbound transfer to unfamiliar/unapproved external destinations."""

    rule_id = "EXFIL-005"
    name = "Unfamiliar Destination Transfer"
    version = "1.0.0"
    description = (
        "Identifies outbound data transfers directed toward destinations outside the "
        "organization's authorized baseline allowlist or known enterprise cloud services."
    )
    score_contribution = 30
    severity_impact = RiskSeverity.HIGH
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        if not context.transfer_events:
            return None

        unfamiliar_transfers = [
            t for t in context.transfer_events if not is_destination_approved(t.destination_host)
        ]
        if not unfamiliar_transfers:
            return None

        primary = unfamiliar_transfers[0]
        linked_evidence: List[Dict[str, Any]] = [
            {
                "evidence_type": "transfer_event",
                "evidence_id": str(primary.id),
                "evidence_provenance": primary.evidence_provenance,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": primary.occurred_at,
                "description": (
                    f"Outbound transfer to unapproved destination: {primary.destination_host} "
                    f"({primary.destination_category}, {primary.byte_count:,} bytes)"
                ),
            }
        ]

        summary = (
            f"Observed outbound transfer of {primary.byte_count:,} bytes to unapproved "
            f"destination '{primary.destination_host}' ({primary.destination_category})."
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
                "unapproved_destination": primary.destination_host,
                "category": primary.destination_category,
                "byte_count": primary.byte_count,
                "protocol": primary.protocol,
                "is_simulated": primary.is_simulated,
            },
            linked_evidence=linked_evidence,
        )
