"""Sensitive Data Detection & Classification API Endpoints (Phase 3).

Exposes detection rules, paginated findings, file classification breakdowns,
and scan sensitivity summary metrics with strict privacy protection.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.detection.rules import DETECTION_RULES
from app.detection.schemas import (
    ClassifiedFileOverviewItem,
    DetectionRuleInfo,
    FileClassificationDetail,
    FileClassificationItem,
    FindingItem,
    PaginatedClassifiedFilesResponse,
    PaginatedFindingsResponse,
    SensitivitySummaryResponse,
)
from app.models.detection import DetectionFinding, FileClassification, ScanDetectionSummary
from app.models.scanner import ScanJob, ScannedFile

router = APIRouter()


@router.get(
    "/detection/rules",
    response_model=List[DetectionRuleInfo],
    summary="Get Detection Rules Catalog",
    description="Returns all active detection rules, categories, descriptions, and baseline confidence ratings.",
    tags=["Sensitive Data Detection"],
)
async def get_detection_rules() -> List[DetectionRuleInfo]:
    """Retrieve catalog of all active detection rules."""
    return [
        DetectionRuleInfo(
            id=rule.rule_id,
            name=rule.name,
            category=rule.category.value,
            confidence=rule.default_confidence.value,
            suggested_classification=rule.suggested_classification.value,
            description=rule.description,
        )
        for rule in DETECTION_RULES
    ]


@router.get(
    "/scans/{scan_id}/sensitivity-summary",
    response_model=SensitivitySummaryResponse,
    summary="Get Scan Sensitivity Summary",
    description="Returns aggregated detection metrics and sensitivity classification breakdown for a scan job.",
    tags=["Sensitive Data Detection"],
)
async def get_sensitivity_summary(
    scan_id: str,
    db: Session = Depends(get_db),
) -> SensitivitySummaryResponse:
    """Retrieve high-level sensitivity classification and detection summary."""
    job = db.query(ScanJob.id).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    summary = (
        db.query(ScanDetectionSummary)
        .filter(ScanDetectionSummary.scan_job_id == scan_id)
        .first()
    )

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection summary for scan job '{scan_id}' is not yet available",
        )

    return SensitivitySummaryResponse(
        scan_job_id=summary.scan_job_id,
        files_inspected=summary.files_inspected,
        sensitive_files_count=summary.sensitive_files_count,
        public_count=summary.public_count,
        internal_count=summary.internal_count,
        confidential_count=summary.confidential_count,
        restricted_count=summary.restricted_count,
        not_assessed_count=summary.not_assessed_count,
        pii_count=summary.pii_count,
        credential_count=summary.credential_count,
        financial_count=summary.financial_count,
        confidential_label_count=summary.confidential_label_count,
        created_at=summary.created_at,
    )


@router.get(
    "/scans/{scan_id}/findings",
    response_model=PaginatedFindingsResponse,
    summary="Get Paginated Scan Findings",
    description="Returns paginated list of detection findings for a specific scan job with optional category and confidence filters.",
    tags=["Sensitive Data Detection"],
)
async def get_scan_findings(
    scan_id: str,
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    size: int = Query(50, ge=1, le=500, description="Items per page"),
    category: Optional[str] = Query(None, description="Filter by category (PII, CREDENTIALS, etc.)"),
    confidence: Optional[str] = Query(None, description="Filter by confidence (LOW, MEDIUM, HIGH)"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    db: Session = Depends(get_db),
) -> PaginatedFindingsResponse:
    """Retrieve paginated detection findings for a scan."""
    job = db.query(ScanJob.id).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    query = (
        db.query(DetectionFinding)
        .join(ScannedFile, DetectionFinding.scanned_file_id == ScannedFile.id)
        .filter(ScannedFile.scan_job_id == scan_id)
    )

    if category:
        query = query.filter(DetectionFinding.category == category.strip().upper())
    if confidence:
        query = query.filter(DetectionFinding.confidence == confidence.strip().upper())
    if rule_id:
        query = query.filter(DetectionFinding.rule_id == rule_id.strip())

    total = query.count()
    offset = (page - 1) * size
    findings = query.order_by(DetectionFinding.detected_at.desc()).offset(offset).limit(size).all()

    items = [
        FindingItem(
            id=f.id,
            scanned_file_id=f.scanned_file_id,
            rule_id=f.rule_id,
            rule_version=f.rule_version,
            category=f.category,
            confidence=f.confidence,
            occurrence_count=f.occurrence_count,
            detected_at=f.detected_at,
        )
        for f in findings
    ]
    pages = (total + size - 1) // size if total > 0 else 0

    return PaginatedFindingsResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/scans/{scan_id}/classified-files",
    response_model=PaginatedClassifiedFilesResponse,
    summary="Get Paginated Classified Files",
    description="Returns files discovered in a scan alongside their sensitivity classifications and finding counts.",
    tags=["Sensitive Data Detection"],
)
async def get_classified_files(
    scan_id: str,
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    size: int = Query(50, ge=1, le=500, description="Items per page"),
    sensitivity: Optional[str] = Query(None, description="Filter by sensitivity (RESTRICTED, CONFIDENTIAL, etc.)"),
    category: Optional[str] = Query(None, description="Filter by detected category presence"),
    search: Optional[str] = Query(None, description="Search by filename"),
    highest_confidence: Optional[str] = Query(None, description="Filter by confidence rating"),
    db: Session = Depends(get_db),
) -> PaginatedClassifiedFilesResponse:
    """Retrieve classified files for a scan job."""
    job = db.query(ScanJob.id).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    query = (
        db.query(ScannedFile, FileClassification)
        .outerjoin(FileClassification, ScannedFile.id == FileClassification.scanned_file_id)
        .filter(ScannedFile.scan_job_id == scan_id)
    )

    if sensitivity:
        query = query.filter(FileClassification.sensitivity_label == sensitivity.strip().upper())

    if highest_confidence:
        query = query.filter(FileClassification.highest_confidence == highest_confidence.strip().upper())

    if search:
        query = query.filter(ScannedFile.filename.ilike(f"%{search.strip()}%"))

    if category:
        subq = (
            db.query(DetectionFinding.scanned_file_id)
            .filter(DetectionFinding.category == category.strip().upper())
            .subquery()
        )
        query = query.filter(ScannedFile.id.in_(subq))

    total = query.count()
    offset = (page - 1) * size
    results = query.order_by(ScannedFile.relative_path.asc()).offset(offset).limit(size).all()

    items = []
    for file_record, class_record in results:
        # Count findings for this file
        findings_count = (
            db.query(DetectionFinding)
            .filter(DetectionFinding.scanned_file_id == file_record.id)
            .count()
        )

        items.append(
            ClassifiedFileOverviewItem(
                file_id=file_record.id,
                scan_job_id=file_record.scan_job_id,
                filename=file_record.filename,
                relative_path=file_record.relative_path,
                file_extension=file_record.file_extension,
                detected_type=file_record.detected_type,
                size_bytes=file_record.size_bytes,
                sensitivity_label=class_record.sensitivity_label if class_record else "NOT_ASSESSED",
                highest_confidence=class_record.highest_confidence if class_record else "N/A",
                inspection_status=class_record.inspection_status if class_record else "unsupported",
                findings_count=findings_count,
                scan_timestamp=file_record.scan_timestamp,
            )
        )

    pages = (total + size - 1) // size if total > 0 else 0

    return PaginatedClassifiedFilesResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/files/{file_id}/classification",
    response_model=FileClassificationDetail,
    summary="Get File Classification Details",
    description="Returns detailed sensitivity classification and findings breakdown for an individual file.",
    tags=["Sensitive Data Detection"],
)
async def get_file_classification(
    file_id: str,
    db: Session = Depends(get_db),
) -> FileClassificationDetail:
    """Retrieve detailed zero-leakage classification breakdown for a file."""
    file_record = db.query(ScannedFile).filter(ScannedFile.id == file_id).first()
    if not file_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scanned file '{file_id}' not found",
        )

    class_record = (
        db.query(FileClassification)
        .filter(FileClassification.scanned_file_id == file_id)
        .first()
    )

    if not class_record:
        # Synthesize fallback record if not yet classified
        classification_item = FileClassificationItem(
            id="unclassified",
            scanned_file_id=file_id,
            sensitivity_label="NOT_ASSESSED",
            policy_version="baseline",
            inspection_status="unsupported",
            explanation="File has not been inspected by the detection engine.",
            highest_confidence="NONE",
            classified_at=file_record.scan_timestamp,
        )
    else:
        classification_item = FileClassificationItem(
            id=class_record.id,
            scanned_file_id=class_record.scanned_file_id,
            sensitivity_label=class_record.sensitivity_label,
            policy_version=class_record.policy_version,
            inspection_status=class_record.inspection_status,
            explanation=class_record.explanation,
            highest_confidence=class_record.highest_confidence,
            classified_at=class_record.classified_at,
        )

    findings_records = (
        db.query(DetectionFinding)
        .filter(DetectionFinding.scanned_file_id == file_id)
        .order_by(DetectionFinding.detected_at.desc())
        .all()
    )

    findings = [
        FindingItem(
            id=f.id,
            scanned_file_id=f.scanned_file_id,
            rule_id=f.rule_id,
            rule_version=f.rule_version,
            category=f.category,
            confidence=f.confidence,
            occurrence_count=f.occurrence_count,
            detected_at=f.detected_at,
        )
        for f in findings_records
    ]

    return FileClassificationDetail(
        file_id=file_record.id,
        filename=file_record.filename,
        relative_path=file_record.relative_path,
        detected_type=file_record.detected_type,
        size_bytes=file_record.size_bytes,
        sha256_hash=file_record.sha256_hash,
        classification=classification_item,
        findings=findings,
    )
