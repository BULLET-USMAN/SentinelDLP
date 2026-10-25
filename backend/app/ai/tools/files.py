"""Read-only file inventory and classification tools."""

from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.detection import FileClassification, DetectionFinding
from app.models.scanner import ScannedFile
from app.ai.security.sanitization import sanitize_evidence_dict


def get_file_classification(db: Session, file_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve sensitivity classification and findings for a file asset."""
    if not file_id:
        return None

    # Query file metadata
    file_record = db.query(ScannedFile).filter(ScannedFile.id == file_id.strip()).first()
    classification = (
        db.query(FileClassification)
        .filter(FileClassification.scanned_file_id == file_id.strip())
        .first()
    )

    if not file_record and not classification:
        return None

    # Retrieve associated findings
    findings = (
        db.query(DetectionFinding)
        .filter(DetectionFinding.scanned_file_id == file_id.strip())
        .all()
    )
    findings_data = [
        {
            "finding_id": f.id,
            "rule_id": f.rule_id,
            "category": f.category,
            "confidence": f.confidence,
            "occurrence_count": f.occurrence_count,
        }
        for f in findings
    ]

    data = {
        "file_id": file_id.strip(),
        "filename": file_record.filename if file_record else "unknown",
        "relative_path": file_record.relative_path if file_record else "unknown",
        "detected_type": file_record.detected_type if file_record else "unknown",
        "size_bytes": file_record.size_bytes if file_record else 0,
        "sensitivity_label": classification.sensitivity_label if classification else "NOT_ASSESSED",
        "classification_explanation": classification.explanation if classification else "No classification recorded",
        "findings": findings_data,
    }
    return sanitize_evidence_dict(data)
