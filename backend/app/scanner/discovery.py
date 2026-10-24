"""Secure Directory Traversal and File Discovery for SentinelDLP (Phase 2).

Safely traverses authorized directory trees with traversal defenses,
symlink escape guards, and cancellation tokens.
"""

import os
from pathlib import Path
import threading
from typing import Generator, Optional, Tuple
from app.core.logging import logger
from app.scanner.validators import is_directory_excluded, validate_path_within_boundary


class ScanCancelledException(Exception):
    """Raised when a scan job is cancelled by user request."""


def discover_files(
    root_path: Path,
    max_files: int = 10000,
    cancellation_event: Optional[threading.Event] = None,
) -> Generator[Tuple[Path, Optional[str]], None, None]:
    """Recursively discover files within the canonical boundary of root_path.

    Yields:
        Tuple of (file_path: Path, skip_reason: Optional[str])
        If skip_reason is not None, the file should be recorded as skipped.

    Raises:
        ScanCancelledException: If cancellation_event is set during traversal.
    """
    canonical_root = Path(os.path.realpath(root_path)).resolve()
    discovered_count = 0

    # Walk directory tree using os.walk with followlinks=False to prevent infinite loops and escapes
    for dirpath, dirnames, filenames in os.walk(str(canonical_root), followlinks=False):
        if cancellation_event and cancellation_event.is_set():
            logger.info("Scan discovery interrupted by cancellation event", extra={"event": "scan_cancelled"})
            raise ScanCancelledException("Scan was cancelled by user request")

        current_dir = Path(dirpath)

        # Validate that current_dir hasn't escaped the boundary
        is_valid_dir, dir_err = validate_path_within_boundary(current_dir, canonical_root)
        if not is_valid_dir:
            logger.warning(
                f"Directory boundary violation skipped: {current_dir} ({dir_err})",
                extra={"event": "boundary_escape_prevented"},
            )
            dirnames.clear()  # Do not recurse into escaped directory
            continue

        # Filter out excluded directories in-place to prevent os.walk from recursing into them
        dirnames[:] = [d for d in dirnames if not is_directory_excluded(d)]

        # Process discovered files in current directory
        for filename in filenames:
            if cancellation_event and cancellation_event.is_set():
                raise ScanCancelledException("Scan was cancelled by user request")

            if discovered_count >= max_files:
                logger.warning(
                    f"Scan reached maximum file ceiling ({max_files} files). Halting further discovery.",
                    extra={"event": "scan_limit_reached", "max_files": max_files},
                )
                return

            file_path = current_dir / filename
            discovered_count += 1

            # Validate individual file boundary (guards against symlink escapes)
            is_valid_file, file_err = validate_path_within_boundary(file_path, canonical_root)
            if not is_valid_file:
                yield file_path, file_err
                continue

            yield file_path, None
