"""Multi-Signal and Low-Certainty Exfiltration Detection Rules (Phase 6).

Implements:
- EXFIL-007: Multi-Signal Potential Exfiltration (Complete Attack Chain)
- EXFIL-008: Insufficient Evidence / Ambiguous Signals (Analyst Triage & Coverage Warning)
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


class MultiSignalExfiltrationRule(BaseExfiltrationRule):
    """EXFIL-007: Detects the multi-step exfiltration kill-chain within the correlation window.

    Full chain:
    1. Sensitive File Activity (access/read/mod)
    2. Archive Creation / Modification (data staging)
    3. Outbound Transfer Evidence (transfer/upload)
    """

    rule_id = "EXFIL-007"
    name = "Multi-Signal Potential Exfiltration"
    version = "1.0.0"
    description = (
        "Detects a complete multi-signal chain consisting of sensitive file activity, "
        "archive creation (staging), and outbound transfer telemetry within the correlation window."
    )
    score_contribution = 50
    severity_impact = RiskSeverity.CRITICAL
    relationship_type = RelationshipType.CIRCUMSTANTIAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        has_sensitive = bool(context.sensitive_file_events)
        has_archive = bool(context.archive_events)
        has_transfer = bool(context.transfer_events)

        if not (has_sensitive and has_archive and has_transfer):
            return None

        # Build comprehensive multi-source evidence
        first_sens = context.sensitive_file_events[0]
        first_arch = context.archive_events[0]
        first_xfer = context.transfer_events[0]

        linked_evidence: List[Dict[str, Any]] = [
            {
                "evidence_type": "file_activity",
                "evidence_id": str(first_sens.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.CIRCUMSTANTIAL.value,
                "timestamp": first_sens.timestamp,
                "description": f"Step 1 (Collection): Sensitive file activity on {first_sens.file_path}",
            },
            {
                "evidence_type": "archive_activity",
                "evidence_id": str(first_arch.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.CIRCUMSTANTIAL.value,
                "timestamp": first_arch.timestamp,
                "description": f"Step 2 (Staging): Archive {first_arch.file_path} created/modified",
            },
            {
                "evidence_type": "transfer_event",
                "evidence_id": str(first_xfer.id),
                "evidence_provenance": first_xfer.evidence_provenance,
                "relationship_nature": RelationshipType.CIRCUMSTANTIAL.value,
                "timestamp": first_xfer.occurred_at,
                "description": f"Step 3 (Exfiltration): Outbound transfer of {first_xfer.byte_count:,} bytes to {first_xfer.destination_host}",
            },
        ]

        summary = (
            f"Correlated full exfiltration chain in {context.window_minutes}m window: "
            f"sensitive file access ({first_sens.file_path}), archive staging ({first_arch.file_path}), "
            f"and outbound transfer ({first_xfer.byte_count:,} bytes to {first_xfer.destination_host})."
        )

        return ExfiltrationRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            relationship_type=self.relationship_type,
            evidence_completeness=EvidenceCompleteness.COMPLETE,
            summary=summary,
            details={
                "sensitive_file": first_sens.file_path,
                "archive_path": first_arch.file_path,
                "destination_host": first_xfer.destination_host,
                "bytes_transferred": first_xfer.byte_count,
                "archive_content_verified": False,
            },
            linked_evidence=linked_evidence,
        )


class InsufficientEvidenceRule(BaseExfiltrationRule):
    """EXFIL-008: Flags ambiguous or isolated signals where evidence is insufficient for high confidence."""

    rule_id = "EXFIL-008"
    name = "Insufficient Evidence"
    version = "1.0.0"
    description = (
        "Identifies isolated or incomplete signals (e.g. transfer to unfamiliar host with "
        "no file activity, or sensitive operations with no transfer telemetry) requiring analyst review."
    )
    score_contribution = 10
    severity_impact = RiskSeverity.LOW
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        # Triggers when there's an isolated signal without corroboration
        has_sensitive = bool(context.sensitive_file_events)
        has_archive = bool(context.archive_events)
        has_transfer = bool(context.transfer_events)

        # Total signal types
        active_signals = sum([1 if has_sensitive else 0, 1 if has_archive else 0, 1 if has_transfer else 0])
        if active_signals != 1:
            return None

        # Determine which signal is present
        signal_desc = "unknown"
        linked_evidence: List[Dict[str, Any]] = []

        if has_transfer:
            t = context.transfer_events[0]
            if is_destination_approved(t.destination_host):
                return None  # Approved single transfer is benign
            signal_desc = f"isolated outbound transfer to {t.destination_host}"
            linked_evidence.append({
                "evidence_type": "transfer_event",
                "evidence_id": str(t.id),
                "evidence_provenance": t.evidence_provenance,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": t.occurred_at,
                "description": f"Isolated transfer: {t.byte_count:,} bytes to {t.destination_host}",
            })
        elif has_archive:
            a = context.archive_events[0]
            signal_desc = f"isolated archive creation ({a.file_path})"
            linked_evidence.append({
                "evidence_type": "archive_activity",
                "evidence_id": str(a.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": a.timestamp,
                "description": f"Isolated archive creation: {a.file_path}",
            })
        elif has_sensitive:
            s = context.sensitive_file_events[0]
            signal_desc = f"sensitive file activity ({s.file_path}) with zero transfer evidence"
            linked_evidence.append({
                "evidence_type": "file_activity",
                "evidence_id": str(s.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": s.timestamp,
                "description": f"Sensitive file activity: {s.file_path}",
            })

        summary = (
            f"Correlation observed {signal_desc} without corroborating telemetry in "
            f"{context.window_minutes}m window. Evidence is insufficient to infer exfiltration."
        )

        return ExfiltrationRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            relationship_type=self.relationship_type,
            evidence_completeness=EvidenceCompleteness.INSUFFICIENT,
            summary=summary,
            details={
                "signal_type": signal_desc,
                "limitation": "No corroborated file or network chain observed.",
            },
            linked_evidence=linked_evidence,
        )
