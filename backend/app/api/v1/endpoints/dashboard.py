"""Centralized SOC Dashboard & Unified Search Endpoints (Phase 8).

Provides:
- Lightweight executive overview aggregation (KPIs, risk distribution, activity stream, priority queue)
- Global metadata search across alerts, investigations, files, and threat indicators
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.dashboard import (
    DashboardOverviewResponse,
    DashboardSearchResponse,
)
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard & Intelligence"])


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    summary="Get SOC Dashboard Overview",
    description="Aggregated executive security posture overview combining security metrics, risk distributions, recent activity, capability health, and priority analyst items.",
)
def get_dashboard_overview(db: Session = Depends(get_db)) -> DashboardOverviewResponse:
    """Retrieve unified executive dashboard payload."""
    return DashboardService.get_overview(db=db)


@router.get(
    "/search",
    response_model=DashboardSearchResponse,
    summary="Global Security Metadata Search",
    description="Fast, sanitized substring search across alerts, investigations, scanned files, rules, and threat indicators.",
)
def global_search(
    q: str = Query(..., min_length=1, max_length=100, description="Search query string"),
    limit: int = Query(15, ge=1, le=50, description="Maximum number of results to return"),
    db: Session = Depends(get_db),
) -> DashboardSearchResponse:
    """Execute global search."""
    return DashboardService.global_search(db=db, query_str=q, limit=limit)
