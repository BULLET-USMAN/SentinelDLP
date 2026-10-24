"""Unit tests for SentinelDLP Risk Scoring and Severity Calculation (Phase 5).

Validates:
- 0–100 bounded score normalization
- Soft diminishing returns formula
- Severity band thresholds
- Evidence completeness and confidence analysis
- Coverage warning isolation
"""

from datetime import datetime, timezone
import pytest
from app.models.monitoring import FileActivityEvent
from app.risk.evidence import evaluate_evidence_quality
from app.risk.rules.base import RuleEvaluationResult
from app.risk.scoring import calculate_risk_score
from app.risk.severity import (
    DetectionConfidence,
    EvidenceCompleteness,
    RiskSeverity,
    score_to_severity,
)


@pytest.fixture
def mock_event() -> FileActivityEvent:
    return FileActivityEvent(
        id="score-test-event",
        root_id="test_root",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="src/sensitive.py",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
        sha256_hash="abcdef1234567890",
    )


def test_score_to_severity_thresholds():
    """Verify exact numerical boundaries for severity bands."""
    assert score_to_severity(0) == RiskSeverity.LOW
    assert score_to_severity(29) == RiskSeverity.LOW
    assert score_to_severity(30) == RiskSeverity.MEDIUM
    assert score_to_severity(59) == RiskSeverity.MEDIUM
    assert score_to_severity(60) == RiskSeverity.HIGH
    assert score_to_severity(79) == RiskSeverity.HIGH
    assert score_to_severity(80) == RiskSeverity.CRITICAL
    assert score_to_severity(100) == RiskSeverity.CRITICAL


def test_zero_rule_matches_produces_baseline_low(mock_event: FileActivityEvent):
    """Event with zero matching detection rules receives 0 score and baseline explanation."""
    score_res = calculate_risk_score(mock_event, [])

    assert score_res.risk_score == 0
    assert score_res.severity == RiskSeverity.LOW
    assert score_res.assessment_status == "assessed"
    assert "baseline parameters" in score_res.explanation
    assert "Filesystem notifications" in score_res.limitations


def test_diminishing_returns_and_score_capping(mock_event: FileActivityEvent):
    """Multiple rules add diminishing contributions and cap cleanly at 100."""
    matches = [
        RuleEvaluationResult(
            rule_id="RULE-1",
            rule_name="Rule 1",
            rule_version="1.0.0",
            score_contribution=45,
            severity_impact=RiskSeverity.MEDIUM,
            explanation="Match 1",
        ),
        RuleEvaluationResult(
            rule_id="RULE-2",
            rule_name="Rule 2",
            rule_version="1.0.0",
            score_contribution=35,
            severity_impact=RiskSeverity.MEDIUM,
            explanation="Match 2",
        ),
        RuleEvaluationResult(
            rule_id="RULE-3",
            rule_name="Rule 3",
            rule_version="1.0.0",
            score_contribution=30,
            severity_impact=RiskSeverity.MEDIUM,
            explanation="Match 3",
        ),
    ]

    # Primary = 45. Secondary = (35 + 30) * 0.6 = 39. Total = 84 (CRITICAL)
    score_res = calculate_risk_score(mock_event, matches)
    assert score_res.risk_score == 84
    assert score_res.severity == RiskSeverity.CRITICAL
    assert "CRITICAL: Immediate analyst triage" in score_res.recommended_action

    # Massive rules must cap at 100
    huge_matches = matches + [
        RuleEvaluationResult(
            rule_id="RULE-4",
            rule_name="Rule 4",
            rule_version="1.0.0",
            score_contribution=60,
            severity_impact=RiskSeverity.HIGH,
            explanation="Match 4",
        )
    ]
    capped_res = calculate_risk_score(mock_event, huge_matches)
    assert capped_res.risk_score <= 100


def test_coverage_warning_isolation(mock_event: FileActivityEvent):
    """Coverage warnings alone do not trigger HIGH threat alerts."""
    matches = [
        RuleEvaluationResult(
            rule_id="RULE-COVERAGE-WARN",
            rule_name="Coverage Failure",
            rule_version="1.0.0",
            score_contribution=10,
            severity_impact=RiskSeverity.LOW,
            explanation="Queue overflow dropped 5 events",
            is_coverage_warning=True,
        )
    ]

    score_res = calculate_risk_score(mock_event, matches)
    assert score_res.assessment_status == "warning"
    assert score_res.severity == RiskSeverity.LOW
    assert score_res.risk_score <= 29
    assert "coverage warning" in score_res.explanation.lower()


def test_evidence_quality_evaluation(mock_event: FileActivityEvent):
    """Verifies evidence completeness and detection confidence levels."""
    # Full telemetry: has hash and classification
    comp, conf = evaluate_evidence_quality(mock_event)
    assert comp == EvidenceCompleteness.COMPLETE
    assert conf == DetectionConfidence.HIGH

    # Deleted file: hash is absent
    del_event = FileActivityEvent(
        id="del-test",
        root_id="test_root",
        event_type="FILE_DELETED",
        is_directory=False,
        relative_path="deleted.txt",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
    )
    comp_del, conf_del = evaluate_evidence_quality(del_event)
    assert comp_del == EvidenceCompleteness.PARTIAL
    assert conf_del == DetectionConfidence.HIGH

    # Coverage failure: INSUFFICIENT completeness
    comp_cov, conf_cov = evaluate_evidence_quality(mock_event, is_coverage_warning=True)
    assert comp_cov == EvidenceCompleteness.INSUFFICIENT
    assert conf_cov == DetectionConfidence.LOW
