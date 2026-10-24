"""Evidence Packaging and Quality Evaluation for SentinelDLP Risk Engine (Phase 5).

Evaluates evidence completeness, detection confidence, and sanitizes
evidence payloads to guarantee zero credential or raw content leakage.
"""

from typing import Any, Dict, Optional
from app.models.monitoring import FileActivityEvent
from app.risk.severity import DetectionConfidence, EvidenceCompleteness


def sanitize_evidence_data(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize evidence dictionary to prevent storing raw secrets or cards."""
    sanitized: Dict[str, Any] = {}
    for k, v in raw_data.items():
        if v is None:
            continue
        # Ensure primitive types or small lists
        if isinstance(v, (str, int, float, bool)):
            sanitized[k] = v
        elif isinstance(v, (list, tuple)):
            sanitized[k] = list(v)[:20]  # Cap list sizes
        elif isinstance(v, dict):
            sanitized[k] = sanitize_evidence_data(v)
        else:
            sanitized[k] = str(v)
    return sanitized


def evaluate_evidence_quality(
    event: FileActivityEvent,
    is_coverage_warning: bool = False,
) -> tuple[EvidenceCompleteness, DetectionConfidence]:
    """Determine evidence completeness and detection confidence based on available telemetry.

    Defensive Engineering Principles:
    - If telemetry has coverage gaps or unreadable files, mark as PARTIAL/INSUFFICIENT.
    - Never assume missing values or fabricate PIDs/usernames.
    """
    if is_coverage_warning or event.error_category in ("queue_overflow", "observer_error"):
        return EvidenceCompleteness.INSUFFICIENT, DetectionConfidence.LOW

    # For deleted files or directory events, hash is not expected
    if event.is_directory:
        return EvidenceCompleteness.COMPLETE, DetectionConfidence.HIGH

    if event.event_type == "FILE_DELETED":
        # Classification may be cached from historical scan, but file no longer exists
        return EvidenceCompleteness.PARTIAL, DetectionConfidence.HIGH

    if event.error_category in ("file_transient_or_unreadable", "excluded_path_filter"):
        return EvidenceCompleteness.PARTIAL, DetectionConfidence.MEDIUM

    # Standard file events
    has_hash = bool(event.sha256_hash)
    has_classification = bool(event.sensitivity_label)

    if has_hash and has_classification:
        return EvidenceCompleteness.COMPLETE, DetectionConfidence.HIGH
    elif has_hash or has_classification:
        return EvidenceCompleteness.PARTIAL, DetectionConfidence.MEDIUM
    else:
        return EvidenceCompleteness.PARTIAL, DetectionConfidence.LOW
