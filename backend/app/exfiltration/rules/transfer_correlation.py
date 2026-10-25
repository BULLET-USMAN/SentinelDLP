"""Transfer-Oriented Exfiltration Detection Rules (Phase 6).

Implements:
- EXFIL-004: Unusual Outbound Transfer Volume
- EXFIL-006: Repeated Outbound Transfers
"""

from typing import Any, Dict, List, Optional
from app.exfiltration.policies import (
    THRESHOLD_CRITICAL_TRANSFER_BYTES,
    THRESHOLD_REPEATED_TRANSFER_COUNT,
    THRESHOLD_UNUSUAL_TRANSFER_BYTES,
)
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


class UnusualTransferVolumeRule(BaseExfiltrationRule):
    """EXFIL-004: Detects outbound transfer exceeding defined volume thresholds."""

    rule_id = "EXFIL-004"
    name = "Unusual Outbound Transfer Volume"
    version = "1.0.0"
    description = (
        "Identifies single or aggregated outbound transfers exceeding volume thresholds "
        f"(>={THRESHOLD_UNUSUAL_TRANSFER_BYTES // (1024*1024)}MB) within the correlation window."
    )
    score_contribution = 25
    severity_impact = RiskSeverity.MEDIUM
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        if not context.transfer_events:
            return None

        large_transfers = [
            t for t in context.transfer_events if t.byte_count >= THRESHOLD_UNUSUAL_TRANSFER_BYTES
        ]
        if not large_transfers:
            return None

        largest = max(large_transfers, key=lambda t: t.byte_count)
        is_critical = largest.byte_count >= THRESHOLD_CRITICAL_TRANSFER_BYTES
        score = 40 if is_critical else 25
        severity = RiskSeverity.HIGH if is_critical else RiskSeverity.MEDIUM

        linked_evidence: List[Dict[str, Any]] = [
            {
                "evidence_type": "transfer_event",
                "evidence_id": str(largest.id),
                "evidence_provenance": largest.evidence_provenance,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": largest.occurred_at,
                "description": (
                    f"Outbound transfer of {largest.byte_count:,} bytes to "
                    f"{largest.destination_host} ({largest.destination_category})."
                ),
            }
        ]

        summary = (
            f"Observed unusual outbound transfer of {largest.byte_count:,} bytes to "
            f"{largest.destination_host} (exceeds threshold of {THRESHOLD_UNUSUAL_TRANSFER_BYTES:,} bytes)."
        )

        return ExfiltrationRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=score,
            severity_impact=severity,
            relationship_type=self.relationship_type,
            evidence_completeness=EvidenceCompleteness.PARTIAL,
            summary=summary,
            details={
                "largest_byte_count": largest.byte_count,
                "destination_host": largest.destination_host,
                "protocol": largest.protocol,
                "is_critical": is_critical,
                "provenance": largest.evidence_provenance,
            },
            linked_evidence=linked_evidence,
        )


class RepeatedOutboundTransfersRule(BaseExfiltrationRule):
    """EXFIL-006: Detects multiple outbound transfers occurring in rapid succession."""

    rule_id = "EXFIL-006"
    name = "Repeated Outbound Transfers"
    version = "1.0.0"
    description = (
        f"Detects repeated outbound transfers (>={THRESHOLD_REPEATED_TRANSFER_COUNT}) "
        "within the correlation window, indicative of chunked or iterative exfiltration."
    )
    score_contribution = 20
    severity_impact = RiskSeverity.MEDIUM
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        count = len(context.transfer_events)
        if count < THRESHOLD_REPEATED_TRANSFER_COUNT:
            return None

        total_bytes = sum(t.byte_count for t in context.transfer_events)
        destinations = {t.destination_host for t in context.transfer_events}

        linked_evidence: List[Dict[str, Any]] = []
        for t in context.transfer_events[:5]:
            linked_evidence.append({
                "evidence_type": "transfer_event",
                "evidence_id": str(t.id),
                "evidence_provenance": t.evidence_provenance,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": t.occurred_at,
                "description": f"Transfer #{len(linked_evidence)+1}: {t.byte_count:,} bytes to {t.destination_host}",
            })

        summary = (
            f"Observed {count} repeated outbound transfers totaling {total_bytes:,} bytes "
            f"across {len(destinations)} destination(s) in {context.window_minutes}m window."
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
                "transfer_count": count,
                "total_bytes": total_bytes,
                "destinations": list(destinations),
            },
            linked_evidence=linked_evidence,
        )
