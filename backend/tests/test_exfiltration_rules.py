"""Unit Tests for Phase 6 Exfiltration Detection Rules (EXFIL-001 through EXFIL-008).

Verifies deterministic evaluation, threshold triggers, explainable summaries,
and strict forensic evidence formatting.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceProvenance,
    RelationshipType,
)
from app.exfiltration.rules.archive_activity import (
    ArchiveFollowedByTransferRule,
    SensitiveActivityArchiveCreationRule,
)
from app.exfiltration.rules.base import ExfiltrationContext
from app.exfiltration.rules.bulk_sensitive_activity import HighVolumeSensitiveActivityRule
from app.exfiltration.rules.multi_signal import (
    InsufficientEvidenceRule,
    MultiSignalExfiltrationRule,
)
from app.exfiltration.rules.transfer_correlation import (
    RepeatedOutboundTransfersRule,
    UnusualTransferVolumeRule,
)
from app.exfiltration.rules.unusual_destination import UnfamiliarDestinationRule
from app.models.exfiltration import TransferEvent
from app.models.monitoring import FileActivityEvent


def make_mock_file_event(
    path: str,
    event_type: str = "CREATE",
    sensitivity: str = None,
    delta_minutes: int = 5,
) -> FileActivityEvent:
    event = MagicMock(spec=FileActivityEvent)
    event.id = f"mock-event-{hash(path) % 10000}"
    event.relative_path = path
    event.file_path = path
    event.event_type = event_type
    event.activity_type = event_type
    event.sensitivity_label = sensitivity
    event.timestamp = datetime.now(timezone.utc) - timedelta(minutes=delta_minutes)
    event.occurred_at = event.timestamp
    return event


def make_mock_transfer(
    dest: str,
    bytes_count: int = 100_000,
    dest_cat: str = "UNKNOWN",
    delta_minutes: int = 2,
    provenance: str = "LAB_SIMULATED",
) -> TransferEvent:
    xfer = MagicMock(spec=TransferEvent)
    xfer.id = f"mock-xfer-{hash(dest) % 10000}"
    xfer.source_endpoint_id = "endpoint-alpha-01"
    xfer.occurred_at = datetime.now(timezone.utc) - timedelta(minutes=delta_minutes)
    xfer.direction = "OUTBOUND"
    xfer.destination_category = dest_cat
    xfer.destination_host = dest
    xfer.protocol = "HTTPS"
    xfer.byte_count = bytes_count
    xfer.evidence_source = "LAB_SYNTHETIC_HARNESS"
    xfer.evidence_provenance = provenance
    xfer.is_simulated = True
    return xfer


class TestExfiltrationRules:
    """Test suite for EXFIL-001 through EXFIL-008."""

    def test_exfil_001_high_volume_sensitive_activity(self):
        rule = HighVolumeSensitiveActivityRule()
        now = datetime.now(timezone.utc)

        # Under threshold: 3 events
        ctx_under = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            sensitive_file_events=[
                make_mock_file_event(f"doc_{i}.xlsx", sensitivity="CONFIDENTIAL") for i in range(3)
            ],
        )
        assert rule.evaluate(ctx_under) is None

        # At/over threshold: 6 events
        ctx_over = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            sensitive_file_events=[
                make_mock_file_event(f"doc_{i}.xlsx", sensitivity="CONFIDENTIAL") for i in range(6)
            ],
        )
        match = rule.evaluate(ctx_over)
        assert match is not None
        assert match.rule_id == "EXFIL-001"
        assert match.score_contribution == 25
        assert match.evidence_completeness == EvidenceCompleteness.PARTIAL

    def test_exfil_002_sensitive_activity_followed_by_archive(self):
        rule = SensitiveActivityArchiveCreationRule()
        now = datetime.now(timezone.utc)

        sens_event = make_mock_file_event("salaries.pdf", sensitivity="RESTRICTED", delta_minutes=8)
        archive_event = make_mock_file_event("staged_data.zip", event_type="CREATE", delta_minutes=5)

        ctx = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            sensitive_file_events=[sens_event],
            archive_events=[archive_event],
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "EXFIL-002"
        assert match.score_contribution == 30
        assert "Archive creation" in match.linked_evidence[1]["description"]
        assert match.details["contents_verified"] is False

    def test_exfil_003_archive_followed_by_transfer(self):
        rule = ArchiveFollowedByTransferRule()
        now = datetime.now(timezone.utc)

        archive_event = make_mock_file_event("backup_stage.tar.gz", event_type="CREATE", delta_minutes=6)
        xfer = make_mock_transfer("mega.nz", bytes_count=12_000_000, delta_minutes=2)

        ctx = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            archive_events=[archive_event],
            transfer_events=[xfer],
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "EXFIL-003"
        assert match.score_contribution == 35

    def test_exfil_004_unusual_transfer_volume(self):
        rule = UnusualTransferVolumeRule()
        now = datetime.now(timezone.utc)

        # Normal small transfer (100KB)
        small_xfer = make_mock_transfer("external.org", bytes_count=100_000)
        ctx_small = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[small_xfer],
        )
        assert rule.evaluate(ctx_small) is None

        # Unusual transfer (10MB)
        large_xfer = make_mock_transfer("external.org", bytes_count=10_000_000)
        ctx_large = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[large_xfer],
        )
        match = rule.evaluate(ctx_large)
        assert match is not None
        assert match.rule_id == "EXFIL-004"
        assert match.score_contribution == 25

        # Critical transfer (60MB)
        huge_xfer = make_mock_transfer("external.org", bytes_count=60_000_000)
        ctx_huge = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[huge_xfer],
        )
        match_huge = rule.evaluate(ctx_huge)
        assert match_huge is not None
        assert match_huge.score_contribution == 40

    def test_exfil_005_unfamiliar_destination(self):
        rule = UnfamiliarDestinationRule()
        now = datetime.now(timezone.utc)

        # Approved destination: backup.internal.corp
        approved_xfer = make_mock_transfer("backup.internal.corp", bytes_count=5_000_000)
        ctx_approved = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[approved_xfer],
        )
        assert rule.evaluate(ctx_approved) is None

        # Unapproved destination: anon-upload.net
        unapproved_xfer = make_mock_transfer("anon-upload.net", bytes_count=2_000_000)
        ctx_unapproved = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[unapproved_xfer],
        )
        match = rule.evaluate(ctx_unapproved)
        assert match is not None
        assert match.rule_id == "EXFIL-005"
        assert match.score_contribution == 30

    def test_exfil_006_repeated_outbound_transfers(self):
        rule = RepeatedOutboundTransfersRule()
        now = datetime.now(timezone.utc)

        # 2 transfers: under threshold
        ctx_under = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[
                make_mock_transfer(f"198.51.100.{i}", bytes_count=1_000_000) for i in range(2)
            ],
        )
        assert rule.evaluate(ctx_under) is None

        # 4 transfers: triggers
        ctx_over = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[
                make_mock_transfer(f"198.51.100.{i}", bytes_count=1_000_000) for i in range(4)
            ],
        )
        match = rule.evaluate(ctx_over)
        assert match is not None
        assert match.rule_id == "EXFIL-006"
        assert match.score_contribution == 20

    def test_exfil_007_multi_signal_potential_exfiltration(self):
        rule = MultiSignalExfiltrationRule()
        now = datetime.now(timezone.utc)

        sens_event = make_mock_file_event("passwords.kdbx", sensitivity="RESTRICTED", delta_minutes=10)
        arch_event = make_mock_file_event("passwords_backup.zip", event_type="CREATE", delta_minutes=8)
        xfer_event = make_mock_transfer("mega.nz", bytes_count=25_000_000, delta_minutes=3)

        ctx = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            sensitive_file_events=[sens_event],
            archive_events=[arch_event],
            transfer_events=[xfer_event],
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "EXFIL-007"
        assert match.score_contribution == 50
        assert match.evidence_completeness == EvidenceCompleteness.COMPLETE
        assert len(match.linked_evidence) == 3

    def test_exfil_008_insufficient_evidence(self):
        rule = InsufficientEvidenceRule()
        now = datetime.now(timezone.utc)

        # Single unapproved transfer with NO archive or sensitive file telemetry
        isolated_xfer = make_mock_transfer("unverified-host.net", bytes_count=500_000)
        ctx = ExfiltrationContext(
            start_time=now - timedelta(minutes=15),
            end_time=now,
            window_minutes=15,
            endpoint_id="endpoint-01",
            transfer_events=[isolated_xfer],
        )
        match = rule.evaluate(ctx)
        assert match is not None
        assert match.rule_id == "EXFIL-008"
        assert match.score_contribution == 10
        assert match.evidence_completeness == EvidenceCompleteness.INSUFFICIENT
