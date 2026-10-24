"""API v1 Router Definition for SentinelDLP."""

from fastapi import APIRouter
from app.api.v1.endpoints import health, placeholder_detection, scans

api_v1_router = APIRouter()

# Health and readiness routes
api_v1_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health & Readiness"],
)

# Phase 2: File Scanner & Inventory routes
api_v1_router.include_router(
    scans.router,
    tags=["File Scanner & Inventory"],
)

# Placeholder detection routes (Phase 3+)
api_v1_router.include_router(
    placeholder_detection.router,
    prefix="/detection",
    tags=["Detection Engine (Phase 3+ Placeholder)"],
)
