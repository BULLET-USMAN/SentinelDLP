"""File Type Classification and Signature Inspection for SentinelDLP (Phase 2).

Combines file extension analysis with lightweight content-signature (magic bytes)
detection to identify supported file types and detect file extension spoofing/discrepancies.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class FileTypeDefinition:
    """Definition of a supported file type and its expected signatures."""

    category: str
    description: str
    extensions: Tuple[str, ...]
    magic_signatures: Tuple[bytes, ...] = ()
    is_text_based: bool = False


# Supported File Catalog
FILE_TYPE_CATALOG: Dict[str, FileTypeDefinition] = {
    # Documents
    "pdf": FileTypeDefinition(
        category="Document",
        description="PDF Document",
        extensions=(".pdf",),
        magic_signatures=(b"%PDF-",),
    ),
    "docx": FileTypeDefinition(
        category="Document",
        description="Microsoft Word Document",
        extensions=(".docx",),
        magic_signatures=(b"PK\x03\x04",),  # OpenXML ZIP container
    ),
    "txt": FileTypeDefinition(
        category="Document",
        description="Plain Text Document",
        extensions=(".txt", ".text", ".log", ".md", ".markdown"),
        is_text_based=True,
    ),
    # Structured Data
    "csv": FileTypeDefinition(
        category="Structured Data",
        description="Comma-Separated Values",
        extensions=(".csv", ".tsv"),
        is_text_based=True,
    ),
    "json": FileTypeDefinition(
        category="Structured Data",
        description="JavaScript Object Notation",
        extensions=(".json",),
        is_text_based=True,
    ),
    "xml": FileTypeDefinition(
        category="Structured Data",
        description="Extensible Markup Language",
        extensions=(".xml",),
        magic_signatures=(b"<?xml", b"<"),
        is_text_based=True,
    ),
    # Source Code and Configuration
    "py": FileTypeDefinition(
        category="Source Code",
        description="Python Source Code",
        extensions=(".py", ".pyw"),
        is_text_based=True,
    ),
    "js": FileTypeDefinition(
        category="Source Code",
        description="JavaScript Source File",
        extensions=(".js", ".mjs", ".cjs"),
        is_text_based=True,
    ),
    "ts": FileTypeDefinition(
        category="Source Code",
        description="TypeScript Source File",
        extensions=(".ts", ".tsx"),
        is_text_based=True,
    ),
    "java": FileTypeDefinition(
        category="Source Code",
        description="Java Source Code",
        extensions=(".java",),
        is_text_based=True,
    ),
    "env": FileTypeDefinition(
        category="Configuration",
        description="Environment Configuration",
        extensions=(".env", ".env.local", ".env.example", ".env.test"),
        is_text_based=True,
    ),
    "yaml": FileTypeDefinition(
        category="Configuration",
        description="YAML Configuration",
        extensions=(".yaml", ".yml"),
        is_text_based=True,
    ),
    "sql": FileTypeDefinition(
        category="Structured Data",
        description="Structured Query Language",
        extensions=(".sql",),
        is_text_based=True,
    ),
    # Images
    "png": FileTypeDefinition(
        category="Image",
        description="Portable Network Graphics",
        extensions=(".png",),
        magic_signatures=(b"\x89PNG\r\n\x1a\n",),
    ),
    "jpg": FileTypeDefinition(
        category="Image",
        description="JPEG Image",
        extensions=(".jpg", ".jpeg"),
        magic_signatures=(b"\xff\xd8\xff",),
    ),
    # Archives
    "zip": FileTypeDefinition(
        category="Archive",
        description="ZIP Compressed Archive",
        extensions=(".zip",),
        magic_signatures=(b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ),
}

# Inverted mapping: extension -> type_key
EXTENSION_MAP: Dict[str, str] = {}
for type_key, defn in FILE_TYPE_CATALOG.items():
    for ext in defn.extensions:
        EXTENSION_MAP[ext.lower()] = type_key


@dataclass
class FileTypeAnalysis:
    """Outcome of file type detection and discrepancy analysis."""

    type_key: str
    description: str
    category: str
    file_extension: str
    is_supported: bool
    type_mismatch: bool
    signature_detected: Optional[str] = None


def read_file_header(file_path: Path, max_bytes: int = 512) -> bytes:
    """Read initial bytes safely without locking or loading entire file."""
    try:
        with open(file_path, "rb") as f:
            return f.read(max_bytes)
    except (OSError, PermissionError):
        return b""


def detect_magic_signature(header: bytes) -> Optional[str]:
    """Inspect magic byte headers for known binary formats."""
    if not header:
        return None

    if header.startswith(b"%PDF-"):
        return "pdf"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip_or_docx"
    if header.strip().startswith(b"<?xml") or (header.strip().startswith(b"<") and b">" in header[:64]):
        return "xml"
    if header.strip().startswith((b"{", b"[")):
        return "json"

    return None


def identify_file_type(file_path: Path, sample_header: Optional[bytes] = None) -> FileTypeAnalysis:
    """Analyze file extension and content signature to classify the file.

    Identifies discrepancies between declared file extension and underlying content.
    """
    filename = file_path.name
    # Handle dotfiles like .env, .env.example
    lower_name = filename.lower()
    if lower_name.startswith(".env"):
        ext = ".env"
    else:
        _, raw_ext = os.path.splitext(lower_name)
        ext = raw_ext if raw_ext else ""

    header = sample_header if sample_header is not None else read_file_header(file_path, max_bytes=64)
    magic_match = detect_magic_signature(header)

    type_key = EXTENSION_MAP.get(ext)
    type_mismatch = False

    if type_key:
        defn = FILE_TYPE_CATALOG[type_key]
        description = defn.description
        category = defn.category
        is_supported = True

        # Check for signature mismatch on binary formats with strict magic numbers
        if defn.magic_signatures and header:
            matches_expected = any(header.startswith(sig) for sig in defn.magic_signatures)
            if not matches_expected:
                type_mismatch = True
    else:
        # Extension is unknown or absent
        if magic_match:
            # File has recognized signature despite unknown extension
            matched_key = "zip" if magic_match == "zip_or_docx" else magic_match
            matched_defn = FILE_TYPE_CATALOG.get(matched_key)
            if matched_defn:
                description = f"{matched_defn.description} (Extension Mismatch)"
                category = matched_defn.category
                type_key = matched_key
                is_supported = True
                type_mismatch = True
            else:
                description = "Unknown File Format"
                category = "Unknown"
                type_key = "unknown"
                is_supported = False
        else:
            description = "Unsupported Format"
            category = "Unknown"
            type_key = "unknown"
            is_supported = False

    return FileTypeAnalysis(
        type_key=type_key or "unknown",
        description=description,
        category=category,
        file_extension=ext or "[none]",
        is_supported=is_supported,
        type_mismatch=type_mismatch,
        signature_detected=magic_match,
    )
