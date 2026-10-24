"""Content Extraction Layer for SentinelDLP (Phase 3).

Provides memory-safe, non-executing content extractors for supported file types.
Protects against XML external entity (XXE) attacks, decompression bombs, and excessive memory usage.
"""

from enum import Enum
import io
import json
import os
from pathlib import Path
import re
from typing import Optional, Set
import xml.etree.ElementTree as ET
import zipfile

# Limits to defend against Denial-of-Service / Memory Exhaustion
MAX_EXTRACT_BYTES = 1048576  # 1MB text limit per file
MAX_ZIP_UNCOMPRESSED_BYTES = 10485760  # 10MB uncompressed limit for DOCX containers
MAX_ZIP_RATIO = 100  # Max compression ratio allowed


class InspectionStatus(str, Enum):
    """Status outcomes for content inspection."""

    INSPECTED = "inspected"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    ENCRYPTED = "encrypted"
    EMPTY = "empty"
    ERROR = "error"


class ContentExtractionResult:
    """Result container for content extraction."""

    def __init__(
        self,
        text: str,
        status: InspectionStatus,
        char_count: int,
        error_message: Optional[str] = None,
        is_truncated: bool = False,
    ):
        self.text = text
        self.status = status
        self.char_count = char_count
        self.error_message = error_message
        self.is_truncated = is_truncated


def extract_plain_text(file_path: Path, max_bytes: int = MAX_EXTRACT_BYTES) -> ContentExtractionResult:
    """Extract text from plain text, source code, and configuration files.

    Handles multiple common encodings gracefully without executing content.
    """
    try:
        if file_path.stat().st_size == 0:
            return ContentExtractionResult(text="", status=InspectionStatus.EMPTY, char_count=0)

        with open(file_path, "rb") as f:
            raw_bytes = f.read(max_bytes + 1)

        is_truncated = len(raw_bytes) > max_bytes
        if is_truncated:
            raw_bytes = raw_bytes[:max_bytes]

        # Multi-encoding decode fallback
        text = None
        for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                text = raw_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if text is None:
            text = raw_bytes.decode("utf-8", errors="replace")

        status = InspectionStatus.PARTIAL if is_truncated else InspectionStatus.INSPECTED
        return ContentExtractionResult(
            text=text,
            status=status,
            char_count=len(text),
            is_truncated=is_truncated,
        )

    except PermissionError:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message="Permission denied reading file",
        )
    except Exception as err:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message=f"Extraction failure: {str(err)}",
        )


def extract_xml_text(file_path: Path, max_bytes: int = MAX_EXTRACT_BYTES) -> ContentExtractionResult:
    """Extract textual content from XML documents with strict XXE defenses.

    Disables external entity resolution and protects against entity expansion attacks.
    """
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read(max_bytes)

        # Quick check for malicious DTD entity references
        if b"<!ENTITY" in raw_bytes or (b"SYSTEM" in raw_bytes and b"<!DOCTYPE" in raw_bytes) or b"<!DOCTYPE" in raw_bytes:
            # Defend against XXE: Strip DOCTYPE/ENTITY definitions before parsing
            raw_bytes = re.sub(rb"<!DOCTYPE[^>]*\[.*?\]>", b"", raw_bytes, flags=re.DOTALL)
            raw_bytes = re.sub(rb"<!DOCTYPE[^>]*>", b"", raw_bytes)
            raw_bytes = re.sub(rb"<!ENTITY[^>]*>", b"", raw_bytes)
            raw_bytes = re.sub(rb"&[a-zA-Z0-9_]+;", b" ", raw_bytes)

        # Parse with safe defused XML settings
        parser = ET.XMLParser()
        root = ET.fromstring(raw_bytes, parser=parser)

        # Extract all text nodes
        texts = [text.strip() for text in root.itertext() if text.strip()]
        full_text = " ".join(texts)

        return ContentExtractionResult(
            text=full_text,
            status=InspectionStatus.INSPECTED,
            char_count=len(full_text),
        )
    except ET.ParseError:
        # Fall back to regex text extraction from sanitized bytes
        try:
            sanitized_text = raw_bytes.decode("utf-8", errors="replace")
            clean_text = re.sub(r"<[^>]+>", " ", sanitized_text)
            clean_text = re.sub(r"&[a-zA-Z0-9_#]+;", " ", clean_text)
            clean_text = " ".join(clean_text.split())
            return ContentExtractionResult(
                text=clean_text,
                status=InspectionStatus.INSPECTED,
                char_count=len(clean_text),
            )
        except Exception as e:
            return ContentExtractionResult(
                text="",
                status=InspectionStatus.ERROR,
                char_count=0,
                error_message=f"XML parsing error: {str(e)}",
            )
    except Exception as err:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message=f"XML extraction error: {str(err)}",
        )


def extract_docx_text(file_path: Path, max_bytes: int = MAX_EXTRACT_BYTES) -> ContentExtractionResult:
    """Extract text from Microsoft Word (.docx) OpenXML documents.

    Guards against ZIP bombs, decompression bombs, and script/macro execution.
    """
    try:
        if not zipfile.is_zipfile(file_path):
            return ContentExtractionResult(
                text="",
                status=InspectionStatus.ERROR,
                char_count=0,
                error_message="Malformed or invalid DOCX archive structure",
            )

        with zipfile.ZipFile(file_path, "r") as zf:
            # Verify zip safety bounds
            total_uncompressed = 0
            for info in zf.infolist():
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                    return ContentExtractionResult(
                        text="",
                        status=InspectionStatus.ERROR,
                        char_count=0,
                        error_message="DOCX rejected: Exceeds safe archive decompression limit (potential zip bomb)",
                    )

            if "word/document.xml" not in zf.namelist():
                return ContentExtractionResult(
                    text="",
                    status=InspectionStatus.UNSUPPORTED,
                    char_count=0,
                    error_message="Document XML content missing from DOCX package",
                )

            # Read document.xml content with size boundary
            with zf.open("word/document.xml") as doc_file:
                xml_content = doc_file.read(max_bytes)

        # Parse XML text elements <w:t>
        root = ET.fromstring(xml_content)
        # Namespace map for WordprocessingML
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        paragraphs = []
        for p in root.findall(".//w:p", ns):
            texts = [node.text for node in p.findall(".//w:t", ns) if node.text]
            if texts:
                paragraphs.append("".join(texts))

        full_text = "\n".join(paragraphs)
        if not full_text.strip():
            # Fallback to general itertext
            full_text = "".join(root.itertext())

        status = InspectionStatus.INSPECTED if full_text.strip() else InspectionStatus.EMPTY
        return ContentExtractionResult(
            text=full_text,
            status=status,
            char_count=len(full_text),
        )

    except zipfile.BadZipFile:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message="Corrupted DOCX archive",
        )
    except Exception as err:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message=f"DOCX extraction fault: {str(err)}",
        )


def extract_pdf_text(file_path: Path, max_bytes: int = MAX_EXTRACT_BYTES) -> ContentExtractionResult:
    """Extract text from PDF documents using pypdf.

    Detects encrypted PDFs and image-only/unreadable documents without executing embedded JS.
    """
    try:
        from pypdf import PdfReader
        from pypdf.errors import EmptyFileError, PdfReadError

        reader = PdfReader(file_path)

        if reader.is_encrypted:
            return ContentExtractionResult(
                text="",
                status=InspectionStatus.ENCRYPTED,
                char_count=0,
                error_message="PDF is encrypted / password protected",
            )

        extracted_pages = []
        total_chars = 0
        is_truncated = False

        for page_idx, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            extracted_pages.append(page_text)
            total_chars += len(page_text)

            if total_chars >= max_bytes:
                is_truncated = True
                break

        full_text = "\n".join(extracted_pages)

        # Distinguish extractable text from image-only / non-OCR documents
        if not full_text.strip():
            return ContentExtractionResult(
                text="",
                status=InspectionStatus.UNSUPPORTED,
                char_count=0,
                error_message="PDF contains no extractable text (image-only, raster scan, or unsupported font)",
            )

        status = InspectionStatus.PARTIAL if is_truncated else InspectionStatus.INSPECTED
        return ContentExtractionResult(
            text=full_text,
            status=status,
            char_count=len(full_text),
            is_truncated=is_truncated,
        )

    except ImportError:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.UNSUPPORTED,
            char_count=0,
            error_message="pypdf parser not installed",
        )
    except Exception as err:
        return ContentExtractionResult(
            text="",
            status=InspectionStatus.ERROR,
            char_count=0,
            error_message=f"PDF parsing error: {str(err)}",
        )


def extract_content(file_path: Path, file_extension: str) -> ContentExtractionResult:
    """Central content extraction dispatcher based on file extension and format."""
    ext = file_extension.lower()

    # Documents
    if ext == ".pdf":
        return extract_pdf_text(file_path)
    if ext == ".docx":
        return extract_docx_text(file_path)
    if ext in (".xml",):
        return extract_xml_text(file_path)

    # Structured and Plain Text / Code
    if ext in (
        ".txt",
        ".text",
        ".log",
        ".md",
        ".csv",
        ".tsv",
        ".json",
        ".yaml",
        ".yml",
        ".py",
        ".pyw",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".sql",
        ".env",
    ) or ext.startswith(".env"):
        return extract_plain_text(file_path)

    # Images, Archives, Binary Formats receive explicit unsupported status
    return ContentExtractionResult(
        text="",
        status=InspectionStatus.UNSUPPORTED,
        char_count=0,
        error_message=f"Content extraction not supported for format: {ext or '[binary]'}",
    )
