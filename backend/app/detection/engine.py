"""Detection Engine Coordinator for SentinelDLP (Phase 3).

Orchestrates safe content extraction, rule evaluation, confidence assignment,
and sensitivity classification for inspected files.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from app.detection.classification import (
    ClassificationOutcome,
    classify_file_sensitivity,
)
from app.detection.extractors import (
    ContentExtractionResult,
    InspectionStatus,
    extract_content,
)
from app.detection.rules import (
    RuleMatchResult,
    evaluate_all_rules,
)


@dataclass
class FileAnalysisReport:
    """Aggregated detection and classification report for a single file."""

    findings: List[RuleMatchResult]
    classification: ClassificationOutcome
    inspection_status: InspectionStatus
    char_count: int
    error_message: Optional[str] = None


class DetectionEngine:
    """Singleton detection coordinator."""

    @staticmethod
    def inspect_and_classify_file(file_path: Path, file_extension: str) -> FileAnalysisReport:
        """Safely extract file content, evaluate detection rules, and classify sensitivity."""
        # 1. Safe content extraction
        extraction: ContentExtractionResult = extract_content(file_path, file_extension)

        # 2. Rule evaluation if text was extracted
        findings: List[RuleMatchResult] = []
        if extraction.text and extraction.status in (InspectionStatus.INSPECTED, InspectionStatus.PARTIAL):
            findings = evaluate_all_rules(extraction.text)

        # 3. Sensitivity Classification
        classification = classify_file_sensitivity(
            findings=findings,
            inspection_status=extraction.status,
            filename=file_path.name,
            file_extension=file_extension,
        )

        # 4. Immediate discard of in-memory extracted text (privacy requirement)
        del extraction.text

        return FileAnalysisReport(
            findings=findings,
            classification=classification,
            inspection_status=extraction.status,
            char_count=extraction.char_count,
            error_message=extraction.error_message,
        )


detection_engine = DetectionEngine()
