"""Centralized Exception Definitions and Handlers for SentinelDLP.

Ensures that internal errors, credentials, and full stack traces are never
leaked to external API consumers.
"""

from typing import Any, Dict, Optional
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.core.logging import logger


class SentinelException(Exception):
    """Base exception for all SentinelDLP application errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class DatabaseConnectionException(SentinelException):
    """Raised when database connectivity fails or times out."""

    def __init__(self, message: str = "Database connection unavailable"):
        super().__init__(
            message=message,
            code="DATABASE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class ConfigurationException(SentinelException):
    """Raised when environment or security configuration is invalid."""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def sentinel_exception_handler(request: Request, exc: SentinelException) -> JSONResponse:
    """Handle custom SentinelDLP exceptions safely."""
    logger.error(
        f"Handled application exception: {exc.code} - {exc.message}",
        extra={"event": "sentinel_exception", "code": exc.code, "status_code": exc.status_code},
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details if exc.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR else {},
            }
        },
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle FastAPI request validation errors cleanly without sensitive disclosures."""
    # Sanitize validation errors to exclude internal reflection details
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error.get("loc", [])),
            "issue": error.get("msg", "Invalid value"),
        })

    logger.warning(
        f"Validation error on {request.method} {request.url.path}",
        extra={"event": "validation_error", "details": errors},
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_FAILED",
                "message": "Input validation failed for one or more fields.",
                "details": errors,
            }
        },
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler to prevent stack traces and internal disclosures from leaking."""
    logger.error(
        f"Unhandled server error on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True,
        extra={"event": "unhandled_exception"},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred. Please contact the administrator.",
                "details": {},
            }
        },
    )
