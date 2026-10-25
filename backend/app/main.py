"""SentinelDLP - Backend Application Entry Point.

AI-Powered Data Loss Prevention & Exfiltration Detection Platform.
Phase 1: Project Foundation, Backend Architecture & Development Environment.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import health as health_endpoint
from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.exceptions import (
    SentinelException,
    sentinel_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.core.logging import logger, setup_logging
from app.core.middleware import (
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.schemas.health import LivenessResponse, ReadinessResponse
from app.services.health_service import HealthService


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifecycle events (startup and shutdown)."""
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.ENVIRONMENT}]",
        extra={"event": "application_startup", "environment": settings.ENVIRONMENT},
    )
    logger.info(
        f"Configured database target: {settings.get_sanitized_db_url()}",
        extra={"event": "database_configured"},
    )
    logger.info(
        f"Allowed CORS origins: {settings.ALLOWED_ORIGINS}",
        extra={"event": "cors_configured"},
    )

    yield

    logger.info(
        f"Shutting down {settings.APP_NAME} v{settings.APP_VERSION}",
        extra={"event": "application_shutdown"},
    )
    # Gracefully stop all active filesystem observers
    try:
        from app.monitoring.manager import monitoring_manager
        monitoring_manager.stop_all()
    except Exception as err:
        logger.error(f"Error terminating monitoring watchers during shutdown: {str(err)}")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="SentinelDLP Core API",
        description=(
            "Defensive cybersecurity platform API for authorized endpoint monitoring, "
            "sensitive data loss prevention, and exfiltration detection."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.DEBUG or settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.DEBUG or settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # Configure Restricted CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
    )

    # Phase 11 Defensive Security Middlewares
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BODY_BYTES)
    app.add_middleware(RateLimitMiddleware)

    # Register Centralized Exception Handlers
    app.add_exception_handler(SentinelException, sentinel_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # Register API v1 Router
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    # Top-level Health Endpoints (Section 4 Specification)
    @app.get(
        "/health/live",
        response_model=LivenessResponse,
        summary="Application Liveness Check",
        tags=["Health & Readiness"],
    )
    async def root_live() -> LivenessResponse:
        """Process liveness probe."""
        return HealthService.check_liveness()

    @app.get(
        "/health/ready",
        response_model=ReadinessResponse,
        summary="Application Readiness Check",
        tags=["Health & Readiness"],
        responses={
            status.HTTP_200_OK: {"description": "All dependencies are operational"},
            status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "One or more dependencies are unavailable"},
        },
    )
    async def root_ready(response: Response) -> ReadinessResponse:
        """Dependency readiness probe."""
        readiness_data, is_ready = HealthService.check_readiness()
        if not is_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return readiness_data

    @app.get(
        "/",
        summary="Root Status",
        tags=["General"],
    )
    async def root() -> dict:
        """Root endpoint returning basic platform identity without disclosing secrets."""
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs" if settings.DEBUG or settings.ENVIRONMENT != "production" else "disabled",
        }

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG,
    )
