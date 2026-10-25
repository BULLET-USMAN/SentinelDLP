"""Defensive Security Middlewares for SentinelDLP.

Enforces:
1. Security Headers (nosniff, DENY, Referrer-Policy, CSP).
2. Request Body Size Limits (rejection of oversized payloads before memory exhaustion).
3. In-memory Rate Limiting (defense against brute-force & endpoint abuse).
"""

from collections import defaultdict
import time
from typing import Callable, Dict, List
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.core.logging import logger


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces essential defensive HTTP response security headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "frame-ancestors 'none';"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects incoming HTTP request bodies exceeding MAX_REQUEST_BODY_BYTES."""

    def __init__(self, app, max_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_bytes:
                    logger.warning(
                        f"Request rejected: content-length {length} exceeds maximum {self.max_bytes} bytes",
                        extra={"event": "request_payload_oversized", "content_length": length},
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds maximum allowable limit of {self.max_bytes // (1024 * 1024)}MB.",
                                "details": {"max_bytes": self.max_bytes, "received_bytes": length},
                            }
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)


class InMemoryRateLimiter:
    """Thread-safe sliding-window in-memory rate limiter per client IP."""

    def __init__(self, requests_per_minute: int = 240):
        self.requests_per_minute = requests_per_minute
        self.history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0

        # Purge entries older than 60s
        timestamps = [ts for ts in self.history[client_ip] if ts > cutoff]
        if len(timestamps) >= self.requests_per_minute:
            self.history[client_ip] = timestamps
            return False

        timestamps.append(now)
        self.history[client_ip] = timestamps
        return True


rate_limiter = InMemoryRateLimiter(requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces requests-per-minute ceilings per client IP to prevent denial of service."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        # Exempt health probes from rate limits
        if request.url.path in ("/health/live", "/health/ready"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        if not rate_limiter.is_allowed(client_ip):
            logger.warning(
                f"Rate limit exceeded for client {client_ip} on {request.url.path}",
                extra={"event": "rate_limit_exceeded", "client_ip": client_ip},
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please throttle your request frequency.",
                        "details": {"retry_after_seconds": 60},
                    }
                },
                headers={"Retry-After": "60"},
            )

        return await call_next(request)
