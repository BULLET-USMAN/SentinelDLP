"""Risk Assessment Endpoints for SentinelDLP (Phase 5).

Provides versioned endpoints to query explainable risk assessments,
analytical score distributions, and detection rule catalog.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.risk.rules import get_rule_catalog
from app.risk.schemas import (
    DetectionRuleCatalogItem,
    PaginatedRiskAssessmentsResponse,
    RiskAssessmentItem,
    RiskStatisticsResponse,
)
from app.risk.services.assessment_service import assessment_service

router = APIRouter(prefix="/risk", tags=["Risk Intelligence"])


@router.get(
    "/assessments",
    response_model=PaginatedRiskAssessmentsResponse,
    summary="List Risk Assessments",
    description="Retrieve a paginated list of explainable risk assessments with multi-parameter filtering.",
)
def list_risk_assessments(
    root_id: Optional[str] = Query(None, description="Filter by authorized root identifier"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    min_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    max_score: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score"),
    status: Optional[str] = Query(None, description="Filter by assessment status (assessed, warning)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db),
) -> PaginatedRiskAssessmentsResponse:
    return assessment_service.list_assessments(
        db=db,
        root_id=root_id,
        severity=severity,
        min_score=min_score,
        max_score=max_score,
        status=status,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=RiskAssessmentItem,
    summary="Get Risk Assessment Details",
    description="Retrieve detailed risk assessment record including granular rule matches and evidence.",
)
def get_risk_assessment_details(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> RiskAssessmentItem:
    item = assessment_service.get_assessment_by_id(assessment_id=assessment_id, db=db)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment '{assessment_id}' not found.",
        )
    return item


@router.get(
    "/statistics",
    response_model=RiskStatisticsResponse,
    summary="Get Risk Statistics",
    description="Retrieve aggregated risk intelligence metrics and score distributions across all monitored activity.",
)
def get_risk_statistics(
    db: Session = Depends(get_db),
) -> RiskStatisticsResponse:
    return assessment_service.get_risk_statistics(db=db)


@router.get(
    "/rules",
    response_model=List[DetectionRuleCatalogItem],
    summary="List Detection Rules Catalog",
    description="List active security detection rules, thresholds, and version information.",
)
def list_detection_rules() -> List[DetectionRuleCatalogItem]:
    return get_rule_catalog()
