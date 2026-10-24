"""File Metadata Extraction for SentinelDLP (Phase 2).

Safely extracts filesystem metadata across Windows and Linux platforms.
Adheres strictly to zero-content-storage principles and privacy bounds.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Optional
from app.scanner.filetypes import FileTypeAnalysis, identify_file_type
from app.scanner.hashing import calculate_sha256


@dataclass
class ExtractedFileMetadata:
    """Encapsulates all extracted file inventory attributes."""

    filename: str
    relative_path: str
    file_extension: str
    detected_type: str
    size_bytes: int
    created_at: Optional[datetime]
    modified_at: Optional[datetime]
    sha256_hash: Optional[str]
    scan_timestamp: datetime
    status: str  # "scanned", "skipped", "error"
    error_message: Optional[str]
    type_mismatch: bool


def _extract_created_time(stat_info: os.stat_result) -> Optional[datetime]:
    """Safely extract file creation / birth timestamp without inventing values.

    On Windows: st_ctime represents creation time.
    On Linux/macOS: st_birthtime is used if available; otherwise None (st_ctime is change time).
    """
    try:
        if hasattr(stat_info, "st_birthtime"):
            return datetime.fromtimestamp(stat_info.st_birthtime, timezone.utc)
        elif os.name == "nt" and hasattr(stat_info, "st_ctime"):
            return datetime.fromtimestamp(stat_info.st_ctime, timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _extract_modified_time(stat_info: os.stat_result) -> Optional[datetime]:
    """Extract last modified timestamp in UTC."""
    try:
        return datetime.fromtimestamp(stat_info.st_mtime, timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def extract_file_metadata(
    file_path: Path,
    root_path: Path,
    compute_hash: bool = True,
    max_size_bytes: Optional[int] = None,
) -> ExtractedFileMetadata:
    """Extract complete file metadata and cryptographic hash safely.

    Handles deleted or modified files during scanning without throwing exceptions.
    """
    scan_time = datetime.now(timezone.utc)
    filename = file_path.name

    # Derive relative path from root
    try:
        relative_path = str(file_path.resolve().relative_to(root_path.resolve())).replace("\\", "/")
    except Exception:
        relative_path = filename

    try:
        stat_info = file_path.stat()
        size_bytes = stat_info.st_size
        created_at = _extract_created_time(stat_info)
        modified_at = _extract_modified_time(stat_info)

        # File classification & signature discrepancy check
        type_analysis: FileTypeAnalysis = identify_file_type(file_path)

        # Hash calculation if enabled
        sha256_hash = None
        error_msg = None
        status = "scanned"

        if compute_hash:
            sha256_hash, _, hash_err = calculate_sha256(file_path, max_size=max_size_bytes)
            if hash_err:
                error_msg = hash_err
                status = "skipped" if "exceeds limit" in hash_err else "error"

        return ExtractedFileMetadata(
            filename=filename,
            relative_path=relative_path,
            file_extension=type_analysis.file_extension,
            detected_type=type_analysis.description,
            size_bytes=size_bytes,
            created_at=created_at,
            modified_at=modified_at,
            sha256_hash=sha256_hash,
            scan_timestamp=scan_time,
            status=status,
            error_message=error_msg,
            type_mismatch=type_analysis.type_mismatch,
        )

    except FileNotFoundError:
        return ExtractedFileMetadata(
            filename=filename,
            relative_path=relative_path,
            file_extension=file_path.suffix.lower() or "[none]",
            detected_type="Unknown",
            size_bytes=0,
            created_at=None,
            modified_at=None,
            sha256_hash=None,
            scan_timestamp=scan_time,
            status="error",
            error_message="File disappeared or was deleted during inspection",
            type_mismatch=False,
        )
    except PermissionError:
        return ExtractedFileMetadata(
            filename=filename,
            relative_path=relative_path,
            file_extension=file_path.suffix.lower() or "[none]",
            detected_type="Unknown",
            size_bytes=0,
            created_at=None,
            modified_at=None,
            sha256_hash=None,
            scan_timestamp=scan_time,
            status="error",
            error_message="Permission denied opening file",
            type_mismatch=False,
        )
    except OSError as err:
        return ExtractedFileMetadata(
            filename=filename,
            relative_path=relative_path,
            file_extension=file_path.suffix.lower() or "[none]",
            detected_type="Unknown",
            size_bytes=0,
            created_at=None,
            modified_at=None,
            sha256_hash=None,
            scan_timestamp=scan_time,
            status="error",
            error_message=f"I/O Error: {err.strerror or 'Filesystem fault'}",
            type_mismatch=False,
        )
