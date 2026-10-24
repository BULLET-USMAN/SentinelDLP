"""Unit tests for SentinelDLP Detection Rules (Phase 5).

Tests individual rule logic, thresholds, and evidence capture across all 8 rules:
- RULE-SENS-MOD
- RULE-RAPID-MOD
- RULE-BULK-RENAME
- RULE-SENS-DEL
- RULE-REPEAT-CHANGE
- RULE-SENS-VOLUME
- RULE-EXT-CHANGE
- RULE-COVERAGE-WARN
"""

from datetime import datetime, timezone
import pytest
from app.models.monitoring import FileActivityEvent
from app.risk.policies import DEFAULT_SCORING_POLICY
from app.risk.rules.bulk_operations import UnusualSensitiveFileActivityVolumeRule
from app.risk.rules.file_activity import RapidFileModificationRule
from app.risk.rules.monitoring_coverage import MonitoringCoverageFailureRule
from app.risk.rules.sensitive_deletion import SensitiveFileDeletionRule
from app.risk.rules.sensitive_files import SensitiveFileModificationRule
from app.risk.rules.suspicious_renames import BulkFileRenamingRule, FileExtensionChangeRule
from app.risk.rules.unusual_changes import RepeatedFileChangesRule
from app.risk.rules.base import TemporalContext
from app.risk.severity import RiskSeverity


@pytest.fixture
def base_event() -> FileActivityEvent:
    """Fixture creating a standard mock FileActivityEvent."""
    return FileActivityEvent(
        id="test-event-01",
        root_id="synthetic_samples",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="docs/confidential_report.docx",
        previous_relative_path=None,
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
        event_source="watchdog",
    )


@pytest.fixture
def empty_context() -> TemporalContext:
    """Fixture creating an empty temporal baseline."""
    return TemporalContext(evaluation_time=datetime.now(timezone.utc))


def test_rule_1_sensitive_file_modification(base_event: FileActivityEvent, empty_context: TemporalContext):
    """Rule 1: Sensitive modification scores modestly and stays in LOW severity."""
    rule = SensitiveFileModificationRule()
    result = rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-SENS-MOD"
    assert result.score_contribution == 25  # RESTRICTED = 25 points
    assert result.severity_impact == RiskSeverity.LOW
    assert "RESTRICTED was modified" in result.explanation

    # Test with PUBLIC file -> Should NOT trigger
    base_event.sensitivity_label = "PUBLIC"
    assert rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY) is None


def test_rule_2_rapid_file_modification(base_event: FileActivityEvent, empty_context: TemporalContext):
    """Rule 2: Detects rapid modification velocity across distinct files."""
    rule = RapidFileModificationRule()

    # Below threshold (e.g., 3 files < 5 threshold)
    empty_context.distinct_modified_files_5m = 3
    assert rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY) is None

    # Meets threshold (5 files)
    empty_context.distinct_modified_files_5m = 6
    empty_context.recent_modified_paths_5m = [f"file_{i}.txt" for i in range(6)]
    result = rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-RAPID-MOD"
    assert result.score_contribution == 25
    assert result.severity_impact == RiskSeverity.MEDIUM
    assert "6 distinct files modified" in result.explanation


def test_rule_3_bulk_file_renaming(empty_context: TemporalContext):
    """Rule 3: Bulk renaming flags volume without asserting confirmed ransomware."""
    rule = BulkFileRenamingRule()
    rename_event = FileActivityEvent(
        id="rename-event-01",
        root_id="synthetic_samples",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="docs/file_b.txt",
        previous_relative_path="docs/file_a.txt",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
    )

    empty_context.distinct_renamed_files_5m = 7
    empty_context.recent_renamed_paths_5m = [f"doc_{i}.bak" for i in range(7)]
    result = rule.evaluate(rename_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-BULK-RENAME"
    assert result.score_contribution == 30
    assert "bulk renaming" in result.explanation.lower()
    # Ensure ransomware is NOT asserted as confirmed fact
    assert "confirmed ransomware" not in result.explanation.lower()


def test_rule_4_sensitive_file_deletion(empty_context: TemporalContext):
    """Rule 4: Detects multiple deletions of classified sensitive assets."""
    rule = SensitiveFileDeletionRule()
    del_event = FileActivityEvent(
        id="del-event-01",
        root_id="synthetic_samples",
        event_type="FILE_DELETED",
        is_directory=False,
        relative_path="payroll/q4_salaries.xlsx",
        sensitivity_label="CONFIDENTIAL",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
    )

    # 3 sensitive files deleted in past 15m
    empty_context.sensitive_deletions_15m = 3
    empty_context.recent_deleted_sensitive_paths_15m = ["file1.csv", "file2.csv", "file3.csv"]
    result = rule.evaluate(del_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-SENS-DEL"
    assert result.score_contribution == 35
    assert result.severity_impact == RiskSeverity.MEDIUM
    assert "3 deletion events" in result.explanation


def test_rule_5_repeated_file_changes(base_event: FileActivityEvent, empty_context: TemporalContext):
    """Rule 5: Flags high churn on the same file path."""
    rule = RepeatedFileChangesRule()

    empty_context.changes_for_this_file_5m = 5  # >= 4 threshold
    result = rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-REPEAT-CHANGE"
    assert result.score_contribution == 20
    assert "5 separate operations" in result.explanation


def test_rule_6_unusual_sensitive_file_volume(base_event: FileActivityEvent, empty_context: TemporalContext):
    """Rule 6: Identifies concentrated operational volume on sensitive assets."""
    rule = UnusualSensitiveFileActivityVolumeRule()

    empty_context.sensitive_events_count_15m = 8  # >= 5 threshold
    result = rule.evaluate(base_event, empty_context, DEFAULT_SCORING_POLICY)

    assert result is not None
    assert result.rule_id == "RULE-SENS-VOLUME"
    assert result.score_contribution == 30
    assert "8 operations on sensitive files" in result.explanation


def test_rule_7_file_extension_change(empty_context: TemporalContext):
    """Rule 7: Extension change telemetry and suspicious extension bonus."""
    rule = FileExtensionChangeRule()

    # Normal extension change: .txt -> .md
    event_normal = FileActivityEvent(
        id="ext-event-01",
        root_id="synthetic_samples",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="docs/notes.md",
        previous_relative_path="docs/notes.txt",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="INTERNAL",
    )
    res_normal = rule.evaluate(event_normal, empty_context, DEFAULT_SCORING_POLICY)
    assert res_normal is not None
    assert res_normal.score_contribution == 20
    assert res_normal.evidence["previous_extension"] == ".txt"
    assert res_normal.evidence["new_extension"] == ".md"

    # Suspicious extension change on RESTRICTED file: .docx -> .locked
    event_suspicious = FileActivityEvent(
        id="ext-event-02",
        root_id="synthetic_samples",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="docs/passwords.locked",
        previous_relative_path="docs/passwords.docx",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
    )
    res_suspicious = rule.evaluate(event_suspicious, empty_context, DEFAULT_SCORING_POLICY)
    assert res_suspicious is not None
    # Base 20 + suspicious bonus 25 = 45 * 1.5 (RESTRICTED multiplier) = 67 points
    assert res_suspicious.score_contribution == 67
    assert res_suspicious.evidence["is_suspicious_extension"] is True


def test_rule_8_monitoring_coverage_failure(empty_context: TemporalContext):
    """Rule 8: Emits coverage warning without asserting confirmed threat."""
    rule = MonitoringCoverageFailureRule()

    event = FileActivityEvent(
        id="overflow-event-01",
        root_id="synthetic_samples",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="data/dropped.bin",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="ignored",
        error_category="queue_overflow",
    )

    result = rule.evaluate(event, empty_context, DEFAULT_SCORING_POLICY)
    assert result is not None
    assert result.rule_id == "RULE-COVERAGE-WARN"
    assert result.is_coverage_warning is True
    assert result.score_contribution == 10
    assert "coverage warning" in result.explanation.lower()
