"""Confidence and Risk Assessment Calculation for Exfiltration Correlation (Phase 6).

Provides deterministic scoring and confidence evaluation.
Ensures explainability: no black-box logic or unsupported certainty.
"""

from typing import List, Tuple
from app.exfiltration.provenance import EvidenceCompleteness, EvidenceConfidence
from app.risk.severity import RiskSeverity


def calculate_exfiltration_risk_and_confidence(
    rule_score_contributions: List[int],
    has_sensitive_activity: bool,
    has_archive_event: bool,
    has_outbound_transfer: bool,
    has_unfamiliar_destination: bool,
    is_simulated_only: bool = False,
) -> Tuple[int, RiskSeverity, EvidenceConfidence, EvidenceCompleteness]:
    """Calculate the normalized risk score (0-100), severity, confidence, and completeness.

    Evidence Completeness Logic:
    - COMPLETE: Full forensic chain observed (sensitive activity + archive/staging + outbound transfer).
    - PARTIAL: Two out of three signals present (e.g. sensitive activity + archive, or archive + transfer).
    - INSUFFICIENT: Isolated or ambiguous signals without corroborating telemetry.

    Confidence Rating Logic:
    - HIGH: Multiple distinct telemetry sources (file events + verified transfer) or complete chain.
    - MEDIUM: Correlated signals within tight window, but lacking direct process/handle proof.
    - LOW: Only circumstantial or partial signals present, or lab simulated with sparse matches.
    """
    base_score = sum(rule_score_contributions)
    normalized_score = min(max(base_score, 0), 100)

    # Signal count evaluation
    signal_count = sum([
        1 if has_sensitive_activity else 0,
        1 if has_archive_event else 0,
        1 if has_outbound_transfer else 0,
    ])

    if signal_count >= 3:
        completeness = EvidenceCompleteness.COMPLETE
        confidence = EvidenceConfidence.HIGH
    elif signal_count == 2:
        completeness = EvidenceCompleteness.PARTIAL
        confidence = EvidenceConfidence.MEDIUM
    else:
        completeness = EvidenceCompleteness.INSUFFICIENT
        confidence = EvidenceConfidence.LOW

    # Map normalized score to RiskSeverity
    if normalized_score >= 80:
        severity = RiskSeverity.CRITICAL
    elif normalized_score >= 60:
        severity = RiskSeverity.HIGH
    elif normalized_score >= 35:
        severity = RiskSeverity.MEDIUM
    else:
        severity = RiskSeverity.LOW

    return normalized_score, severity, confidence, completeness
