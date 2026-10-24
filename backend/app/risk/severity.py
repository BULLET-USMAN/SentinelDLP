"""Severity, Confidence, and Completeness Definitions for Risk Engine (Phase 5).

Provides standardized enums and threshold mappings for:
- Risk Severity (LOW, MEDIUM, HIGH, CRITICAL)
- Evidence Completeness (COMPLETE, PARTIAL, INSUFFICIENT)
- Detection Confidence (LOW, MEDIUM, HIGH)
- Alert Lifecycle Status (OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)
"""

from enum import Enum


class RiskSeverity(str, Enum):
    """Numerical band severity classifications (0–100 range)."""

    LOW = "LOW"            # 0–29
    MEDIUM = "MEDIUM"      # 30–59
    HIGH = "HIGH"          # 60–79
    CRITICAL = "CRITICAL"  # 80–100


class EvidenceCompleteness(str, Enum):
    """Reflects the completeness of supporting filesystem telemetry."""

    COMPLETE = "COMPLETE"          # Full metadata, hash, and content classification available
    PARTIAL = "PARTIAL"            # File deleted, transient, or classification pending
    INSUFFICIENT = "INSUFFICIENT"  # Coverage gaps, unreadable attributes, or missing context


class DetectionConfidence(str, Enum):
    """Confidence level that the observed telemetry accurately represents the event."""

    LOW = "LOW"        # Incomplete telemetry, coverage warning, or transient file
    MEDIUM = "MEDIUM"  # Standard event without full re-inspection
    HIGH = "HIGH"      # Validated event with cryptographic hash and confirmed classification


class AlertStatus(str, Enum):
    """SOC Analyst alert triage lifecycle states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# Valid state transitions
VALID_STATUS_TRANSITIONS = {
    AlertStatus.OPEN: {AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.OPEN},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED},
    AlertStatus.RESOLVED: {AlertStatus.OPEN},
    AlertStatus.FALSE_POSITIVE: {AlertStatus.OPEN},
}


def score_to_severity(score: int) -> RiskSeverity:
    """Map a normalized 0–100 integer score into its corresponding severity band."""
    if score >= 80:
        return RiskSeverity.CRITICAL
    if score >= 60:
        return RiskSeverity.HIGH
    if score >= 30:
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW
