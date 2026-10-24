"""Security Boundaries and Path Validation for SentinelDLP (Phase 2).

Enforces strict defense-in-depth access controls:
- Canonical path validation.
- Traversal attempt detection.
- Allowlisted scan root enforcement.
- Symlink and junction escape prevention.
"""

import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from app.core.config import settings
from app.core.exceptions import SentinelException


class SecurityBoundaryException(SentinelException):
    """Raised when an unauthorized path traversal or security violation is detected."""

    def __init__(self, message: str, code: str = "SECURITY_BOUNDARY_VIOLATION"):
        super().__init__(message=message, code=code, status_code=403)


def get_authorized_root_info(root_id: str) -> Tuple[str, Path]:
    """Retrieve and validate an authorized scan root by its configured identifier.

    Returns:
        Tuple of (display_name: str, canonical_root_path: Path)

    Raises:
        SecurityBoundaryException: If root_id is not authorized or does not exist.
    """
    authorized_roots = settings.get_authorized_roots()
    if root_id not in authorized_roots:
        raise SecurityBoundaryException(
            f"Scan root identifier '{root_id}' is not in the authorized administrator allowlist.",
            code="UNAUTHORIZED_SCAN_ROOT",
        )

    root_meta = authorized_roots[root_id]
    raw_path = root_meta.get("path")
    if not raw_path:
        raise SecurityBoundaryException(
            f"Configured scan root '{root_id}' missing path configuration.",
            code="INVALID_ROOT_CONFIGURATION",
        )

    # Resolve canonical realpath
    canonical_path = Path(os.path.realpath(raw_path))
    if not canonical_path.exists():
        # Create directory automatically if it is the synthetic samples directory
        if root_id == "synthetic_samples":
            canonical_path.mkdir(parents=True, exist_ok=True)
        else:
            raise SecurityBoundaryException(
                f"Authorized root directory does not exist on filesystem: '{root_id}'",
                code="SCAN_ROOT_NOT_FOUND",
            )

    if not canonical_path.is_dir():
        raise SecurityBoundaryException(
            f"Configured scan root is not a directory: '{root_id}'",
            code="SCAN_ROOT_NOT_DIRECTORY",
        )

    return root_meta.get("name", root_id), canonical_path


def validate_path_within_boundary(target_path: Path, root_path: Path) -> Tuple[bool, Optional[str]]:
    """Verify that a target path resides strictly within the canonical boundary of root_path.

    Defends against:
    - Dot-dot (..) traversal sequences.
    - Symlinks pointing outside root.
    - Windows NTFS junctions / reparse points escaping boundary.

    Returns:
        Tuple of (is_valid: bool, error_reason: Optional[str])
    """
    try:
        canonical_root = Path(os.path.realpath(root_path)).resolve()
        canonical_target = Path(os.path.realpath(target_path)).resolve()

        # Check if canonical target is a subpath of canonical root
        # In Python 3.9+, is_relative_to() or relative_to()
        try:
            canonical_target.relative_to(canonical_root)
        except ValueError:
            return False, f"Path traversal detected: target '{target_path.name}' resolves outside scan root."

        # Verify symlink / reparse boundary: if the path is a symlink, verify its real destination
        if os.path.islink(target_path):
            real_target = Path(os.path.realpath(target_path))
            try:
                real_target.relative_to(canonical_root)
            except ValueError:
                return False, f"Symlink escape detected: '{target_path.name}' points outside boundary."

        return True, None

    except (OSError, PermissionError) as err:
        return False, f"Filesystem error verifying path boundary: {str(err)}"


def is_directory_excluded(dir_name: str) -> bool:
    """Check if a directory name matches configured exclusion lists."""
    normalized = dir_name.strip().lower()
    for pattern in settings.EXCLUDED_DIR_NAMES:
        if normalized == pattern.lower():
            return True
    return False
