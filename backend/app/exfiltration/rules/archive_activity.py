"""Archive-Related Exfiltration Correlation Rules (Phase 6).

Implements:
- EXFIL-002: Sensitive Activity Followed by Archive Creation (Staging)
- EXFIL-003: Archive Activity Followed by Transfer Evidence

Strict Principle: Archive contents are NEVER assumed without cryptographic or verified
stream evidence. Events occurring near archive creation are tracked as temporal correlation.
"""

from typing import Any, Dict, List, Optional
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


class SensitiveActivityArchiveCreationRule(BaseExfiltrationRule):
    """EXFIL-002: Detects sensitive file activity followed temporally by archive file creation."""

    rule_id = "EXFIL-002"
    name = "Sensitive Activity Followed by Archive Creation"
    version = "1.0.0"
    description = (
        "Identifies sensitive file read or access events temporally correlated with "
        "archive file creation (e.g. .zip, .tar, .7z), suggesting potential data staging."
    )
    score_contribution = 30
    severity_impact = RiskSeverity.HIGH
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        if not context.sensitive_file_events or not context.archive_events:
            return None

        # Sort events chronologically
        archive_creates = [
            e for e in context.archive_events
            if e.activity_type.upper() in ("CREATE", "CREATED", "MODIFY", "MODIFIED")
        ]
        if not archive_creates:
            return None

        first_sensitive = min(context.sensitive_file_events, key=lambda e: e.timestamp)
        # Find archive created after or around first sensitive event
        correlated_archives = [
            a for a in archive_creates if a.timestamp >= first_sensitive.timestamp
        ] or archive_creates

        earliest_archive = correlated_archives[0]

        linked_evidence: List[Dict[str, Any]] = [
            {
                "evidence_type": "file_activity",
                "evidence_id": str(first_sensitive.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": first_sensitive.timestamp,
                "description": f"Sensitive file access: {first_sensitive.file_path}",
            },
            {
                "evidence_type": "archive_activity",
                "evidence_id": str(earliest_archive.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": earliest_archive.timestamp,
                "description": (
                    f"Archive creation ({earliest_archive.file_path}) observed after sensitive activity. "
                    "Archive contents unverified."
                ),
            },
        ]

        summary = (
            f"Sensitive file activity on {first_sensitive.file_path} was followed by "
            f"creation/modification of archive {earliest_archive.file_path} within {context.window_minutes}m window."
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
                "sensitive_file": first_sensitive.file_path,
                "archive_path": earliest_archive.file_path,
                "archive_timestamp": earliest_archive.timestamp.isoformat(),
                "contents_verified": False,
            },
            linked_evidence=linked_evidence,
        )


class ArchiveFollowedByTransferRule(BaseExfiltrationRule):
    """EXFIL-003: Detects archive file activity followed temporally by outbound transfer evidence."""

    rule_id = "EXFIL-003"
    name = "Archive Activity Followed by Transfer Evidence"
    version = "1.0.0"
    description = (
        "Identifies archive file creation/modification followed temporally by outbound data "
        "transfer telemetry, suggesting potential staging and subsequent exfiltration."
    )
    score_contribution = 35
    severity_impact = RiskSeverity.HIGH
    relationship_type = RelationshipType.TEMPORAL

    def evaluate(self, context: ExfiltrationContext) -> Optional[ExfiltrationRuleMatch]:
        if not context.archive_events or not context.transfer_events:
            return None

        earliest_archive = min(context.archive_events, key=lambda e: e.timestamp)
        subsequent_transfers = [
            t for t in context.transfer_events if t.occurred_at >= earliest_archive.timestamp
        ] or context.transfer_events

        if not subsequent_transfers:
            return None

        transfer = subsequent_transfers[0]

        linked_evidence: List[Dict[str, Any]] = [
            {
                "evidence_type": "archive_activity",
                "evidence_id": str(earliest_archive.id),
                "evidence_provenance": EvidenceProvenance.OBSERVED.value,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": earliest_archive.timestamp,
                "description": f"Archive file operation: {earliest_archive.file_path}",
            },
            {
                "evidence_type": "transfer_event",
                "evidence_id": str(transfer.id),
                "evidence_provenance": transfer.evidence_provenance,
                "relationship_nature": RelationshipType.TEMPORAL.value,
                "timestamp": transfer.occurred_at,
                "description": (
                    f"Outbound transfer to {transfer.destination_host} ({transfer.byte_count:,} bytes) "
                    f"following archive creation."
                ),
            },
        ]

        summary = (
            f"Archive activity on {earliest_archive.file_path} was followed by outbound transfer "
            f"of {transfer.byte_count:,} bytes to {transfer.destination_host}."
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
                "archive_path": earliest_archive.file_path,
                "destination_host": transfer.destination_host,
                "byte_count": transfer.byte_count,
                "transfer_provenance": transfer.evidence_provenance,
                "contents_verified": False,
            },
            linked_evidence=linked_evidence,
        )
