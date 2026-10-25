"""Security Alert Endpoints for SentinelDLP (Phase 5).

Provides versioned endpoints to query security alerts, update triage lifecycle
status with validated state transitions, and view immutable audit history.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.auth import AuthUser, require_analyst, require_readonly
from app.db.session import get_db
from app.risk.schemas import (
    AlertStatisticsResponse,
    PaginatedSecurityAlertsResponse,
    SecurityAlertDetail,
    SecurityAlertItem,
    UpdateAlertStatusRequest,
)
from app.risk.services.alert_service import alert_service
from app.risk.services.assessment_service import assessment_service

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get(
    "",
    response_model=PaginatedSecurityAlertsResponse,
    summary="List Security Alerts",
    description="Retrieve a paginated list of actionable security alerts with status and severity filters.",
)
def list_security_alerts(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    root_id: Optional[str] = Query(None, description="Filter by authorized directory root"),
    min_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum threat score"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_readonly),
) -> PaginatedSecurityAlertsResponse:
    return assessment_service.list_alerts(
        db=db,
        status=status_filter,
        severity=severity,
        root_id=root_id,
        min_score=min_score,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/statistics",
    response_model=AlertStatisticsResponse,
    summary="Get Alert Statistics",
    description="Retrieve operational SOC alert triage counts by status and severity.",
)
def get_alert_statistics(
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_readonly),
) -> AlertStatisticsResponse:
    return assessment_service.get_alert_statistics(db=db)


@router.get(
    "/{alert_id}",
    response_model=SecurityAlertDetail,
    summary="Get Alert Details",
    description="Retrieve comprehensive security alert details, linked risk assessment, evidence, and audit history.",
)
def get_alert_details(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_readonly),
) -> SecurityAlertDetail:
    alert = assessment_service.get_alert_by_id(alert_id=alert_id, db=db)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return alert


@router.patch(
    "/{alert_id}/status",
    response_model=SecurityAlertDetail,
    summary="Update Alert Status",
    description="Update an alert's triage lifecycle status (e.g., ACKNOWLEDGED, INVESTIGATING, RESOLVED) with analyst notes.",
)
def update_alert_status(
    alert_id: str,
    payload: UpdateAlertStatusRequest,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_analyst),
) -> SecurityAlertDetail:
    try:
        alert_service.update_alert_status(
            alert_id=alert_id,
            new_status=payload.status,
            analyst_notes=payload.analyst_notes,
            performed_by=payload.performed_by or current_user.username,
            db=db,
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )

    # Return refreshed detail view
    updated = assessment_service.get_alert_by_id(alert_id=alert_id, db=db)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return updated
