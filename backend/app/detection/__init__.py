"""Detection package for SentinelDLP (Phase 3)."""

from app.detection.engine import DetectionEngine, FileAnalysisReport, detection_engine
from app.detection.classification import ClassificationOutcome, classify_file_sensitivity
from app.detection.extractors import ContentExtractionResult, InspectionStatus, extract_content
from app.detection.rules import (
    DETECTION_RULES,
    ConfidenceLevel,
    DetectionCategory,
    RuleMatchResult,
    SensitivityLevel,
    evaluate_all_rules,
)

__all__ = [
    "DetectionEngine",
    "FileAnalysisReport",
    "detection_engine",
    "ClassificationOutcome",
    "classify_file_sensitivity",
    "ContentExtractionResult",
    "InspectionStatus",
    "extract_content",
    "ConfidenceLevel",
    "DetectionCategory",
    "RuleMatchResult",
    "SensitivityLevel",
    "evaluate_all_rules",
    "DETECTION_RULES",
]
