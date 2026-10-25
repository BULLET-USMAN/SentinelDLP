"""Investigation Timeline Synthesizer for SentinelDLP (Phase 6).

Constructs a structured chronological forensic timeline for an exfiltration investigation.
Strictly labels each timeline event with explicit evidence provenance and relationship type.
"""

import json
from typing import List
from app.exfiltration.schemas import ExfiltrationTimelineItem
from app.models.exfiltration import ExfiltrationInvestigation


def build_investigation_timeline(investigation: ExfiltrationInvestigation) -> List[ExfiltrationTimelineItem]:
    """Generate a chronological timeline merging evidence links and rule correlation matches."""
    items: List[ExfiltrationTimelineItem] = []

    # 1. Process all linked evidence
    for link in investigation.evidence_links:
        category = "FILE_ACTIVITY"
        if link.evidence_type == "transfer_event":
            category = "OUTBOUND_TRANSFER"
        elif link.evidence_type == "archive_activity":
            category = "ARCHIVE_EVENT"
        elif link.evidence_type == "risk_assessment":
            category = "RISK_ALERT"

        metadata = {}
        if link.metadata_json:
            try:
                metadata = json.loads(link.metadata_json)
            except Exception:
                metadata = {"raw": link.metadata_json}

        items.append(
            ExfiltrationTimelineItem(
                id=f"ev-{link.id}",
                timestamp=link.timestamp,
                title=f"Evidence: {link.evidence_type.replace('_', ' ').title()}",
                description=link.description,
                category=category,
                evidence_provenance=link.evidence_provenance,
                relationship_type=link.relationship_nature,
                severity=investigation.severity,
                metadata=metadata,
            )
        )

    # 2. Process all correlation rule records
    for record in investigation.correlation_records:
        rule_meta = {}
        if record.details_json:
            try:
                rule_meta = json.loads(record.details_json)
            except Exception:
                rule_meta = {"raw": record.details_json}

        items.append(
            ExfiltrationTimelineItem(
                id=f"rule-{record.id}",
                timestamp=record.matched_at,
                title=f"Rule Triggered: {record.rule_id} ({record.rule_name})",
                description=record.summary,
                category="CORRELATION_RULE",
                evidence_provenance="INFERRED",
                relationship_type=record.relationship_type,
                severity=investigation.severity,
                metadata={
                    "rule_id": record.rule_id,
                    "rule_version": record.rule_version,
                    "score_contribution": record.score_contribution,
                    **rule_meta,
                },
            )
        )

    # Sort chronologically by timestamp
    items.sort(key=lambda x: x.timestamp)
    return items
