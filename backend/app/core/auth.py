"""Authentication and Role-Based Access Control (RBAC) for SentinelDLP.

Enforces defensive security perimeter controls:
- Token & API key validation with timing-safe comparison (secrets.compare_digest).
- Role hierarchy: ADMIN > ANALYST > READONLY.
- Object-level & endpoint-level authorization boundaries.
- Zero credential exposure in exception responses.
"""

from enum import Enum
import secrets
from typing import Callable, List, Optional
from fastapi import Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import logger


class Role(str, Enum):
    """User and service authorization roles."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    READONLY = "READONLY"


class AuthUser(BaseModel):
    """Authenticated user context containing identity and role."""
    username: str
    role: Role

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_analyst(self) -> bool:
        return self.role in (Role.ADMIN, Role.ANALYST)


# Role hierarchy weights for privilege comparisons
ROLE_HIERARCHY = {
    Role.ADMIN: 3,
    Role.ANALYST: 2,
    Role.READONLY: 1,
}


def _extract_token(
    x_api_key: Optional[str],
    authorization: Optional[str],
    api_key_query: Optional[str] = None,
) -> Optional[str]:
    """Extract raw token string from X-API-Key, Authorization Bearer, or query param."""
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        parts = authorization.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "apikey"):
            return parts[1].strip()
        return parts[0].strip()
    if api_key_query:
        return api_key_query.strip()
    return None


def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    api_key: Optional[str] = Query(None, alias="api_key"),
) -> AuthUser:
    """Validate token credentials and return authenticated user context.

    Raises:
        HTTPException(401): If authentication is required and credentials are missing or invalid.
    """
    if not settings.AUTH_ENABLED:
        # Development override: default to administrative analyst
        return AuthUser(username="dev_analyst", role=Role.ADMIN)

    token = _extract_token(x_api_key, authorization, api_key)
    if not token:
        if not settings.AUTH_ENFORCED and settings.ENVIRONMENT != "production":
            # Permissive dev fallback
            return AuthUser(username="local_guest", role=Role.ADMIN)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials missing. Provide 'X-API-Key' or 'Authorization: Bearer <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Timing-safe token comparison against configured role keys
    if secrets.compare_digest(token, settings.ADMIN_API_KEY):
        return AuthUser(username="admin_operator", role=Role.ADMIN)

    if secrets.compare_digest(token, settings.ANALYST_API_KEY):
        return AuthUser(username="soc_analyst", role=Role.ANALYST)

    if secrets.compare_digest(token, settings.READONLY_API_KEY):
        return AuthUser(username="auditor", role=Role.READONLY)

    logger.warning("Failed authentication attempt with invalid API key", extra={"event": "auth_failure"})
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(min_role: Role) -> Callable[[AuthUser], AuthUser]:
    """Dependency factory checking that the authenticated caller possesses at least min_role privileges."""
    def role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        user_weight = ROLE_HIERARCHY.get(user.role, 0)
        required_weight = ROLE_HIERARCHY.get(min_role, 0)

        if user_weight < required_weight:
            logger.warning(
                f"Unauthorized action attempt by user '{user.username}' ({user.role.value}) requiring {min_role.value}",
                extra={"event": "rbac_denial", "user": user.username, "required_role": min_role.value},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: operation requires '{min_role.value}' role privileges.",
            )
        return user

    return role_checker


# Convenient standard role dependencies
require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_readonly = require_role(Role.READONLY)
