"""Unit and Integration Tests for Phase 6 Exfiltration Correlation & Timeline Engine."""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from app.exfiltration.confidence import calculate_exfiltration_risk_and_confidence
from app.exfiltration.policies import is_archive_file, is_destination_approved
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceConfidence,
    EvidenceProvenance,
    RelationshipType,
)
from app.exfiltration.timeline import build_investigation_timeline
from app.models.exfiltration import (
    CorrelationRecord,
    ExfiltrationInvestigation,
    InvestigationEvidenceLink,
)
from app.risk.severity import RiskSeverity


def test_archive_file_detection():
    """Verify archive detection on various extensions without assuming internal contents."""
    assert is_archive_file("backup.zip") is True
    assert is_archive_file("data.tar.gz") is True
    assert is_archive_file("archive.7z") is True
    assert is_archive_file("dump.rar") is True
    assert is_archive_file("document.pdf") is False
    assert is_archive_file("spreadsheet.xlsx") is False
    assert is_archive_file("") is False


def test_approved_destination_allowlist():
    """Verify baseline approved destinations allowlist."""
    assert is_destination_approved("backup.internal.corp") is True
    assert is_destination_approved("github.com/org/repo") is True
    assert is_destination_approved("storage.googleapis.com") is True
    assert is_destination_approved("mega.nz") is False
    assert is_destination_approved("198.51.100.25") is False
    assert is_destination_approved("pastebin.com") is False


def test_risk_and_confidence_scoring_matrix():
    """Verify quantitative scoring, severity mapping, confidence, and completeness."""
    # Complete chain: sensitive + archive + transfer
    score, sev, conf, comp = calculate_exfiltration_risk_and_confidence(
        rule_score_contributions=[50, 30, 25],
        has_sensitive_activity=True,
        has_archive_event=True,
        has_outbound_transfer=True,
        has_unfamiliar_destination=True,
    )
    assert score == 100  # Capped at 100
    assert sev == RiskSeverity.CRITICAL
    assert conf == EvidenceConfidence.HIGH
    assert comp == EvidenceCompleteness.COMPLETE

    # Partial chain: sensitive + archive only
    score_p, sev_p, conf_p, comp_p = calculate_exfiltration_risk_and_confidence(
        rule_score_contributions=[30],
        has_sensitive_activity=True,
        has_archive_event=True,
        has_outbound_transfer=False,
        has_unfamiliar_destination=False,
    )
    assert score_p == 30
    assert sev_p == RiskSeverity.LOW
    assert conf_p == EvidenceConfidence.MEDIUM
    assert comp_p == EvidenceCompleteness.PARTIAL

    # Insufficient chain: transfer only
    score_i, sev_i, conf_i, comp_i = calculate_exfiltration_risk_and_confidence(
        rule_score_contributions=[10],
        has_sensitive_activity=False,
        has_archive_event=False,
        has_outbound_transfer=True,
        has_unfamiliar_destination=False,
    )
    assert score_i == 10
    assert conf_i == EvidenceConfidence.LOW
    assert comp_i == EvidenceCompleteness.INSUFFICIENT


def test_investigation_timeline_generation():
    """Verify timeline items are sorted chronologically and include explicit provenance and relationships."""
    now = datetime.now(timezone.utc)

    inv = MagicMock(spec=ExfiltrationInvestigation)
    inv.id = "inv-001"
    inv.severity = "HIGH"

    link1 = MagicMock(spec=InvestigationEvidenceLink)
    link1.id = "l1"
    link1.evidence_type = "file_activity"
    link1.evidence_provenance = EvidenceProvenance.OBSERVED.value
    link1.relationship_nature = RelationshipType.TEMPORAL.value
    link1.timestamp = now - timedelta(minutes=10)
    link1.description = "Accessed confidential file"
    link1.metadata_json = None

    link2 = MagicMock(spec=InvestigationEvidenceLink)
    link2.id = "l2"
    link2.evidence_type = "transfer_event"
    link2.evidence_provenance = EvidenceProvenance.LAB_SIMULATED.value
    link2.relationship_nature = RelationshipType.TEMPORAL.value
    link2.timestamp = now - timedelta(minutes=3)
    link2.description = "Outbound transfer of 15MB"
    link2.metadata_json = None

    rec1 = MagicMock(spec=CorrelationRecord)
    rec1.id = "r1"
    rec1.rule_id = "EXFIL-002"
    rec1.rule_name = "Sensitive Activity Followed by Archive Creation"
    rec1.rule_version = "1.0.0"
    rec1.score_contribution = 30
    rec1.relationship_type = RelationshipType.TEMPORAL.value
    rec1.matched_at = now - timedelta(minutes=5)
    rec1.summary = "Rule match summary"
    rec1.details_json = None

    inv.evidence_links = [link1, link2]
    inv.correlation_records = [rec1]

    timeline = build_investigation_timeline(inv)
    assert len(timeline) == 3

    # Check chronological ordering: link1 (10m ago) -> rec1 (5m ago) -> link2 (3m ago)
    assert timeline[0].id == "ev-l1"
    assert timeline[0].evidence_provenance == "OBSERVED"
    assert timeline[0].category == "FILE_ACTIVITY"

    assert timeline[1].id == "rule-r1"
    assert timeline[1].evidence_provenance == "INFERRED"
    assert timeline[1].category == "CORRELATION_RULE"

    assert timeline[2].id == "ev-l2"
    assert timeline[2].evidence_provenance == "LAB_SIMULATED"
    assert timeline[2].category == "OUTBOUND_TRANSFER"
