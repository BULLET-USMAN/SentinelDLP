"""Scanner & Inventory API Endpoints for SentinelDLP (Phase 2).

Provides versioned endpoints for root discovery, scan job initiation,
inventory inspection, filtering, pagination, and cancellation.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.exceptions import SentinelException
from app.db.session import get_db
from app.models.scanner import ScanJob, ScannedFile
from app.scanner.engine import scanner_engine
from app.scanner.schemas import (
    AuthorizedRootInfo,
    PaginatedFilesResponse,
    ScanCancellationResponse,
    ScanCreateRequest,
    ScanJobSummary,
    ScannedFileItem,
)
from app.scanner.validators import SecurityBoundaryException

router = APIRouter()


@router.get(
    "/scanner/roots",
    response_model=List[AuthorizedRootInfo],
    summary="Get Authorized Scan Roots",
    description="Returns administrator-configured authorized directories available for scanning.",
)
async def get_authorized_roots() -> List[AuthorizedRootInfo]:
    """Retrieve allowlisted scan roots."""
    roots = settings.get_authorized_roots()
    result = []
    for root_id, meta in roots.items():
        result.append(
            AuthorizedRootInfo(
                root_id=root_id,
                name=meta.get("name", root_id),
                path=meta.get("path", ""),
                description=meta.get("description", ""),
            )
        )
    return result


@router.post(
    "/scans",
    response_model=ScanJobSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate File Scan Job",
    description="Starts a bounded background scan job against an authorized root directory.",
)
async def create_scan_job(request: ScanCreateRequest, db: Session = Depends(get_db)) -> ScanJobSummary:
    """Start a scan job for the given root identifier."""
    try:
        scan_id = scanner_engine.start_scan_job(request.root_id)
    except SecurityBoundaryException as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=err.message)
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to start scan: {str(err)}")

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan job creation error")

    return _to_job_summary(job)


@router.get(
    "/scans",
    response_model=List[ScanJobSummary],
    summary="Get Scan Job History",
    description="Returns historical scan runs sorted by start timestamp descending.",
)
async def list_scans(
    limit: int = Query(20, ge=1, le=100, description="Max jobs to return"),
    offset: int = Query(0, ge=0, description="Records offset"),
    db: Session = Depends(get_db),
) -> List[ScanJobSummary]:
    """List historical scan jobs."""
    jobs = (
        db.query(ScanJob)
        .order_by(ScanJob.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_to_job_summary(j) for j in jobs]


@router.get(
    "/scans/{scan_id}",
    response_model=ScanJobSummary,
    summary="Get Scan Job Status",
    description="Returns live progress or historical outcome for a specific scan job.",
)
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)) -> ScanJobSummary:
    """Get status and metrics for a specific scan job."""
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan job '{scan_id}' not found")
    return _to_job_summary(job)


@router.get(
    "/scans/{scan_id}/files",
    response_model=PaginatedFilesResponse,
    summary="Get Paginated File Inventory",
    description="Returns discovered files for a scan job with filtering, search, and pagination.",
)
async def get_scan_files(
    scan_id: str,
    page: int = Query(1, ge=1, description="Page index (1-based)"),
    size: int = Query(50, ge=1, le=500, description="Page size limit"),
    search: Optional[str] = Query(None, description="Filename substring search"),
    file_type: Optional[str] = Query(None, description="Filter by detected file type"),
    status: Optional[str] = Query(None, description="Filter by status (scanned, skipped, error)"),
    type_mismatch: Optional[bool] = Query(None, description="Filter for signature mismatch anomalies"),
    db: Session = Depends(get_db),
) -> PaginatedFilesResponse:
    """Retrieve paginated file inventory records for a scan job."""
    # Verify job existence
    job = db.query(ScanJob.id).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan job '{scan_id}' not found")

    query = db.query(ScannedFile).filter(ScannedFile.scan_job_id == scan_id)

    # Apply filters
    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(ScannedFile.filename.ilike(search_filter))

    if file_type:
        query = query.filter(ScannedFile.detected_type.ilike(f"%{file_type.strip()}%"))

    if status:
        query = query.filter(ScannedFile.status == status.strip().lower())

    if type_mismatch is not None:
        query = query.filter(ScannedFile.type_mismatch == type_mismatch)

    total_records = query.count()
    offset = (page - 1) * size
    records = query.order_by(ScannedFile.relative_path.asc()).offset(offset).limit(size).all()

    items = [
        ScannedFileItem(
            id=r.id,
            scan_job_id=r.scan_job_id,
            filename=r.filename,
            relative_path=r.relative_path,
            file_extension=r.file_extension,
            detected_type=r.detected_type,
            size_bytes=r.size_bytes,
            created_at=r.created_at,
            modified_at=r.modified_at,
            sha256_hash=r.sha256_hash,
            scan_timestamp=r.scan_timestamp,
            status=r.status,
            error_message=r.error_message,
            type_mismatch=r.type_mismatch,
        )
        for r in records
    ]

    total_pages = (total_records + size - 1) // size if total_records > 0 else 0

    return PaginatedFilesResponse(
        items=items,
        total=total_records,
        page=page,
        size=size,
        pages=total_pages,
    )


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanCancellationResponse,
    summary="Cancel Running Scan Job",
    description="Requests cancellation of an ongoing file scan job.",
)
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanCancellationResponse:
    """Cancel a scan job in progress."""
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan job '{scan_id}' not found")

    if job.status not in ("pending", "running"):
        return ScanCancellationResponse(
            scan_id=scan_id,
            status=job.status,
            message=f"Scan job is already {job.status}; cancellation not applicable.",
        )

    was_cancelled = scanner_engine.cancel_scan_job(scan_id)
    if was_cancelled:
        return ScanCancellationResponse(
            scan_id=scan_id,
            status="cancelling",
            message="Cancellation signal delivered to scanner worker.",
        )

    # If worker had already terminated or was pending
    job.status = "cancelled"
    db.commit()
    return ScanCancellationResponse(
        scan_id=scan_id,
        status="cancelled",
        message="Scan job marked as cancelled.",
    )


def _to_job_summary(job: ScanJob) -> ScanJobSummary:
    """Helper to convert ScanJob ORM model to Pydantic schema."""
    duration = None
    if job.completed_at and job.started_at:
        duration = round((job.completed_at - job.started_at).total_seconds(), 2)

    return ScanJobSummary(
        id=job.id,
        root_id=job.root_id,
        root_path=job.root_path,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        files_discovered=job.files_discovered,
        files_processed=job.files_processed,
        files_skipped=job.files_skipped,
        error_count=job.error_count,
        total_bytes_processed=job.total_bytes_processed,
        duration_seconds=duration,
        error_message=job.error_message,
    )
