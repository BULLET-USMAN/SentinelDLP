"""Health Endpoints for SentinelDLP.

Provides /live and /ready probes for monitoring and orchestrators.
"""

from fastapi import APIRouter, Response, status
from app.schemas.health import LivenessResponse, ReadinessResponse
from app.services.health_service import HealthService

router = APIRouter()


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Application Liveness Probe",
    description="Returns whether the application process is running and receiving traffic.",
)
async def get_live() -> LivenessResponse:
    """Check process liveness."""
    return HealthService.check_liveness()


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Application Readiness Probe",
    description="Validates that all external dependencies (PostgreSQL database) are reachable.",
    responses={
        status.HTTP_200_OK: {"description": "All dependencies are operational"},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "One or more dependencies are down or unreachable"},
    },
)
async def get_ready(response: Response) -> ReadinessResponse:
    """Check application readiness."""
    readiness_data, is_ready = HealthService.check_readiness()
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return readiness_data
