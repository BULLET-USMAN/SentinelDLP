"""Health Verification Service for SentinelDLP.

Provides service logic for process liveness and dependency readiness verification.
"""

from datetime import datetime, timezone
from typing import Tuple
from app.core.config import settings
from app.db.session import check_db_connectivity
from app.schemas.health import ComponentHealth, LivenessResponse, ReadinessResponse


class HealthService:
    """Encapsulates health and readiness inspection logic."""

    @staticmethod
    def check_liveness() -> LivenessResponse:
        """Return the application process liveness status."""
        return LivenessResponse(
            status="live",
            app_name=settings.APP_NAME,
            version=settings.APP_VERSION,
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def check_readiness() -> Tuple[ReadinessResponse, bool]:
        """Verify readiness of all external dependencies.

        Returns:
            Tuple of (ReadinessResponse, is_ready: bool)
        """
        db_up, db_msg, db_latency = check_db_connectivity()

        components = {
            "database": ComponentHealth(
                status="up" if db_up else "down",
                message=db_msg,
                latency_ms=db_latency,
            )
        }

        is_ready = db_up
        overall_status = "ready" if is_ready else "unready"

        response = ReadinessResponse(
            status=overall_status,
            app_name=settings.APP_NAME,
            version=settings.APP_VERSION,
            timestamp=datetime.now(timezone.utc),
            components=components,
        )

        return response, is_ready
