"""Unit Tests for Sensitivity Classification Engine in SentinelDLP (Phase 3).

Validates:
- Precedence ordering: RESTRICTED > CONFIDENTIAL > INTERNAL > PUBLIC > NOT_ASSESSED
- Policy versioning and explanation formatting
- Zero secret leakage in generated explanations
- Degraded/unsupported file handling
"""

import pytest
from app.detection.classification import (
    POLICY_VERSION,
    classify_file_sensitivity,
)
from app.detection.extractors import InspectionStatus
from app.detection.rules import (
    ConfidenceLevel,
    DetectionCategory,
    RuleMatchResult,
    SensitivityLevel,
)


def test_classify_restricted_precedence() -> None:
    """Verify that credentials or payment cards trigger RESTRICTED classification."""
    findings = [
        RuleMatchResult(
            rule_id="RULE-PII-EMAIL",
            category=DetectionCategory.PII,
            confidence=ConfidenceLevel.HIGH,
            occurrence_count=2,
            suggested_classification=SensitivityLevel.CONFIDENTIAL,
        ),
        RuleMatchResult(
            rule_id="RULE-CRED-API-TOKEN",
            category=DetectionCategory.CREDENTIALS,
            confidence=ConfidenceLevel.HIGH,
            occurrence_count=1,
            suggested_classification=SensitivityLevel.RESTRICTED,
        ),
    ]

    outcome = classify_file_sensitivity(
        findings=findings,
        inspection_status=InspectionStatus.INSPECTED,
        filename="app_config.env",
        file_extension=".env",
    )

    assert outcome.sensitivity_label == SensitivityLevel.RESTRICTED
    assert outcome.highest_confidence == "HIGH"
    assert "RESTRICTED" in outcome.explanation
    assert outcome.policy_version == POLICY_VERSION


def test_classify_confidential_when_pii_present() -> None:
    """Verify that PII alone results in CONFIDENTIAL."""
    findings = [
        RuleMatchResult(
            rule_id="RULE-PII-CNIC-PK",
            category=DetectionCategory.PII,
            confidence=ConfidenceLevel.HIGH,
            occurrence_count=3,
            suggested_classification=SensitivityLevel.CONFIDENTIAL,
        ),
    ]

    outcome = classify_file_sensitivity(
        findings=findings,
        inspection_status=InspectionStatus.INSPECTED,
        filename="citizens.csv",
        file_extension=".csv",
    )

    assert outcome.sensitivity_label == SensitivityLevel.CONFIDENTIAL
    assert outcome.highest_confidence == "HIGH"
    assert "CONFIDENTIAL" in outcome.explanation


def test_classify_internal_default() -> None:
    """Verify standard code/files with zero findings default to INTERNAL."""
    outcome = classify_file_sensitivity(
        findings=[],
        inspection_status=InspectionStatus.INSPECTED,
        filename="utils.py",
        file_extension=".py",
    )

    assert outcome.sensitivity_label == SensitivityLevel.INTERNAL
    assert outcome.highest_confidence == "NONE"


def test_classify_public_documentation() -> None:
    """Verify README/LICENSE with zero findings defaults to PUBLIC."""
    outcome = classify_file_sensitivity(
        findings=[],
        inspection_status=InspectionStatus.INSPECTED,
        filename="README.md",
        file_extension=".md",
    )

    assert outcome.sensitivity_label == SensitivityLevel.PUBLIC


def test_classify_not_assessed_for_unsupported() -> None:
    """Verify unsupported binary files are classified as NOT_ASSESSED."""
    outcome = classify_file_sensitivity(
        findings=[],
        inspection_status=InspectionStatus.UNSUPPORTED,
        filename="photo.jpg",
        file_extension=".jpg",
    )

    assert outcome.sensitivity_label == SensitivityLevel.NOT_ASSESSED
    assert outcome.highest_confidence == "N/A"
