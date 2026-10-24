"""Health Check Schemas for SentinelDLP.

Provides standard contract for liveness and readiness responses.
"""

from datetime import datetime
from typing import Dict, Optional
from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    """Schema for GET /health/live."""

    status: str = Field(default="live", description="Application process status")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application semantic version")
    timestamp: datetime = Field(..., description="UTC timestamp of the health check")


class ComponentHealth(BaseModel):
    """Individual component status within readiness check."""

    status: str = Field(..., description="Component state: up or down")
    message: Optional[str] = Field(None, description="Descriptive status message without sensitive data")
    latency_ms: Optional[float] = Field(None, description="Check execution time in milliseconds")


class ReadinessResponse(BaseModel):
    """Schema for GET /health/ready."""

    status: str = Field(..., description="Overall readiness: ready or unready")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application semantic version")
    timestamp: datetime = Field(..., description="UTC timestamp of the health check")
    components: Dict[str, ComponentHealth] = Field(..., description="Status breakdown for dependencies")
