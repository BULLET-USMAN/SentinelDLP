"""Sensitivity Classification Engine and Policy Precedence for SentinelDLP (Phase 3).

Applies deterministic, policy-based rules to assign one of:
- RESTRICTED (Highest sensitivity: Credentials, Private Keys, Payment Cards)
- CONFIDENTIAL (PII, Financial Records, Confidentiality Markers)
- INTERNAL (Organizational source code, documentation, operational configs)
- PUBLIC (Explicitly designated public documents with zero sensitive findings)
- NOT_ASSESSED (Incomplete, unsupported, encrypted, or failed extractions)

Generates human-readable evidence explanations for security auditors.
"""

from dataclasses import dataclass
from typing import List, Tuple
from app.detection.extractors import InspectionStatus
from app.detection.rules import (
    DetectionCategory,
    RuleMatchResult,
    SensitivityLevel,
)

POLICY_VERSION = "2026.1-defensive-baseline"


@dataclass
class ClassificationOutcome:
    """Outcome of sensitivity evaluation."""

    sensitivity_label: SensitivityLevel
    policy_version: str
    inspection_status: InspectionStatus
    explanation: str
    highest_confidence: str


def classify_file_sensitivity(
    findings: List[RuleMatchResult],
    inspection_status: InspectionStatus,
    filename: str,
    file_extension: str,
) -> ClassificationOutcome:
    """Evaluate file sensitivity classification based on detection findings and inspection status."""
    # 1. Non-inspected or degraded inspection handling
    if inspection_status == InspectionStatus.ENCRYPTED:
        return ClassificationOutcome(
            sensitivity_label=SensitivityLevel.NOT_ASSESSED,
            policy_version=POLICY_VERSION,
            inspection_status=inspection_status,
            explanation="File is password-protected or encrypted; content inspection could not be completed.",
            highest_confidence="N/A",
        )

    if inspection_status in (InspectionStatus.UNSUPPORTED, InspectionStatus.ERROR):
        return ClassificationOutcome(
            sensitivity_label=SensitivityLevel.NOT_ASSESSED,
            policy_version=POLICY_VERSION,
            inspection_status=inspection_status,
            explanation="File format unsupported for direct content inspection or inspection encountered I/O errors.",
            highest_confidence="N/A",
        )

    # 2. Evaluate Findings Precedence
    if not findings:
        # Check if file has an explicit public designation
        lower_name = filename.lower()
        if lower_name.startswith("readme") or lower_name.startswith("license"):
            return ClassificationOutcome(
                sensitivity_label=SensitivityLevel.PUBLIC,
                policy_version=POLICY_VERSION,
                inspection_status=inspection_status,
                explanation="Standard public repository documentation with zero sensitive indicators detected.",
                highest_confidence="NONE",
            )

        return ClassificationOutcome(
            sensitivity_label=SensitivityLevel.INTERNAL,
            policy_version=POLICY_VERSION,
            inspection_status=inspection_status,
            explanation="Standard organizational asset; no sensitive PII, credentials, or financial indicators detected.",
            highest_confidence="NONE",
        )

    # Determine highest confidence among findings
    has_high = any(f.confidence.value == "HIGH" for f in findings)
    has_med = any(f.confidence.value == "MEDIUM" for f in findings)
    highest_confidence = "HIGH" if has_high else ("MEDIUM" if has_med else "LOW")

    # Evaluate RESTRICTED triggers (Credentials, Private Keys, Payment Cards)
    restricted_findings = [f for f in findings if f.suggested_classification == SensitivityLevel.RESTRICTED]
    if restricted_findings:
        categories = {f.category.value for f in restricted_findings}
        total_occurrences = sum(f.occurrence_count for f in restricted_findings)
        rules = ", ".join(f.rule_id for f in restricted_findings)
        explanation = (
            f"Classified as RESTRICTED due to detection of high-impact secrets or payment data "
            f"({total_occurrences} occurrence(s) across categories: {', '.join(categories)}; Rules: {rules})."
        )
        return ClassificationOutcome(
            sensitivity_label=SensitivityLevel.RESTRICTED,
            policy_version=POLICY_VERSION,
            inspection_status=inspection_status,
            explanation=explanation,
            highest_confidence=highest_confidence,
        )

    # Evaluate CONFIDENTIAL triggers (PII, Financial Records, Confidentiality Markers)
    confidential_findings = [f for f in findings if f.suggested_classification == SensitivityLevel.CONFIDENTIAL]
    if confidential_findings:
        categories = {f.category.value for f in confidential_findings}
        total_occurrences = sum(f.occurrence_count for f in confidential_findings)
        rules = ", ".join(f.rule_id for f in confidential_findings)
        explanation = (
            f"Classified as CONFIDENTIAL due to identification of sensitive data "
            f"({total_occurrences} occurrence(s) across categories: {', '.join(categories)}; Rules: {rules})."
        )
        return ClassificationOutcome(
            sensitivity_label=SensitivityLevel.CONFIDENTIAL,
            policy_version=POLICY_VERSION,
            inspection_status=inspection_status,
            explanation=explanation,
            highest_confidence=highest_confidence,
        )

    # Fallback to INTERNAL
    return ClassificationOutcome(
        sensitivity_label=SensitivityLevel.INTERNAL,
        policy_version=POLICY_VERSION,
        inspection_status=inspection_status,
        explanation="Ordinary organizational asset with minor indicators that do not meet elevated confidentiality thresholds.",
        highest_confidence=highest_confidence,
    )
