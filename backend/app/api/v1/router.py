"""API v1 Router Definition for SentinelDLP."""

from fastapi import APIRouter
from app.api.v1.endpoints import health, placeholder_detection

api_v1_router = APIRouter()

# Health and readiness routes
api_v1_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health & Readiness"],
)

# Placeholder detection routes
api_v1_router.include_router(
    placeholder_detection.router,
    prefix="/detection",
    tags=["Detection Engine (Phase 2+ Placeholder)"],
)
