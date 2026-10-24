"""SentinelDLP Intelligent File Scanner Package (Phase 2)."""

from app.scanner.engine import scanner_engine, ScanEngine
from app.scanner.filetypes import identify_file_type, FileTypeAnalysis
from app.scanner.hashing import calculate_sha256
from app.scanner.metadata import extract_file_metadata, ExtractedFileMetadata
from app.scanner.validators import get_authorized_root_info, validate_path_within_boundary

__all__ = [
    "scanner_engine",
    "ScanEngine",
    "identify_file_type",
    "FileTypeAnalysis",
    "calculate_sha256",
    "extract_file_metadata",
    "ExtractedFileMetadata",
    "get_authorized_root_info",
    "validate_path_within_boundary",
]
