"""SHA-256 Streaming File Hashing for SentinelDLP (Phase 2).

Provides high-throughput, chunk-based cryptographic hashing with strict memory
boundaries and comprehensive filesystem exception handling.
"""

import hashlib
from pathlib import Path
from typing import Optional, Tuple
from app.core.config import settings
from app.core.logging import logger


class HashingError(Exception):
    """Raised when an unrecoverable hashing failure occurs."""


def calculate_sha256(
    file_path: Path,
    chunk_size: int = settings.CHUNK_SIZE_BYTES,
    max_size: Optional[int] = settings.MAX_FILE_SIZE_BYTES,
) -> Tuple[Optional[str], int, Optional[str]]:
    """Compute SHA-256 hash using memory-safe streaming reads.

    Args:
        file_path: Canonical Path to the file.
        chunk_size: Read buffer size in bytes (defaults to 64KB).
        max_size: Optional size threshold in bytes; files exceeding this are skipped.

    Returns:
        Tuple of (hex_digest, bytes_processed, error_message)
    """
    try:
        # Check current size safely
        stat_info = file_path.stat()
        file_size = stat_info.st_size

        if max_size is not None and file_size > max_size:
            return None, 0, f"File size ({file_size} bytes) exceeds limit ({max_size} bytes)"

        hasher = hashlib.sha256()
        bytes_read = 0

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_read += len(chunk)

        # Detect truncation / concurrent modification
        if bytes_read != file_size:
            logger.warning(
                f"File size modified during hashing: {file_path.name} (read {bytes_read} vs stat {file_size})",
                extra={"event": "hash_size_mismatch", "file": file_path.name},
            )

        return hasher.hexdigest(), bytes_read, None

    except FileNotFoundError:
        return None, 0, "File disappeared or deleted during scan"
    except PermissionError:
        return None, 0, "Permission denied accessing file"
    except OSError as err:
        return None, 0, f"Filesystem I/O error: {err.strerror or 'Unknown error'}"
    except Exception as err:
        logger.error(
            f"Unexpected hashing failure on {file_path.name}: {str(err)}",
            exc_info=True,
            extra={"event": "hashing_exception"},
        )
        return None, 0, "Internal hashing error"
