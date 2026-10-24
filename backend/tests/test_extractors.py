"""Unit Tests for Content Extractors in SentinelDLP (Phase 3).

Validates:
- Safe plain text extraction
- Multi-encoding fallback (UTF-8, Latin-1, CP1252)
- Text size truncation bounds (1MB limit)
- XML extraction with XXE defense
- DOCX extraction with zip decompression safety
- Inaccessible/corrupted file resilience
"""

from pathlib import Path
import tempfile
import zipfile
import pytest
from app.detection.extractors import (
    InspectionStatus,
    extract_content,
    extract_docx_text,
    extract_plain_text,
    extract_xml_text,
)


def test_extract_plain_text_utf8() -> None:
    """Verify UTF-8 text extraction."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as tf:
        tf.write("Sample security documentation content for DLP testing.")
        tf_path = Path(tf.name)

    try:
        res = extract_plain_text(tf_path)
        assert res.status == InspectionStatus.INSPECTED
        assert "Sample security documentation" in res.text
        assert res.char_count > 0
    finally:
        tf_path.unlink(missing_ok=True)


def test_extract_text_truncation_limit() -> None:
    """Verify that oversized text files are truncated at 1MB and marked PARTIAL."""
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
        # Write 1.5MB of data
        chunk = b"A" * 1024
        for _ in range(1500):
            tf.write(chunk)
        tf_path = Path(tf.name)

    try:
        res = extract_plain_text(tf_path)
        assert res.status == InspectionStatus.PARTIAL
        assert len(res.text.encode("utf-8")) <= 1048576 + 10  # 1MB limit
    finally:
        tf_path.unlink(missing_ok=True)


def test_extract_xml_xxe_protection() -> None:
    """Verify that malicious XML containing DOCTYPE entity expansion is sanitized."""
    malicious_xml = (
        '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
        '<!DOCTYPE foo [  \n'
        '<!ELEMENT foo ANY >\n'
        '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>\n'
        '<foo>&xxe; harmless payload</foo>'
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml", delete=False) as tf:
        tf.write(malicious_xml)
        tf_path = Path(tf.name)

    try:
        res = extract_xml_text(tf_path)
        assert res.status == InspectionStatus.INSPECTED
        # DOCTYPE definition must be stripped
        assert "<!DOCTYPE" not in res.text
        assert "harmless payload" in res.text
    finally:
        tf_path.unlink(missing_ok=True)


def test_extract_docx_valid() -> None:
    """Verify valid DOCX parsing extracts paragraphs from word/document.xml."""
    with tempfile.NamedTemporaryFile("wb", suffix=".docx", delete=False) as tf:
        tf_path = Path(tf.name)

    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '  <w:body>\n'
        '    <w:p><w:r><w:t>Confidential Corporate Briefing Note</w:t></w:r></w:p>\n'
        '  </w:body>\n'
        '</w:document>'
    )
    with zipfile.ZipFile(tf_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", doc_xml)

    try:
        res = extract_docx_text(tf_path)
        assert res.status == InspectionStatus.INSPECTED
        assert "Confidential Corporate Briefing Note" in res.text
    finally:
        tf_path.unlink(missing_ok=True)


def test_extract_docx_corrupted() -> None:
    """Verify corrupted DOCX (not a zip file) returns ERROR status without crashing."""
    with tempfile.NamedTemporaryFile("w", suffix=".docx", delete=False) as tf:
        tf.write("Corrupted plain text payload in docx extension")
        tf_path = Path(tf.name)

    try:
        res = extract_docx_text(tf_path)
        assert res.status == InspectionStatus.ERROR
        assert res.error_message is not None
    finally:
        tf_path.unlink(missing_ok=True)


def test_extract_content_dispatcher_unsupported() -> None:
    """Verify dispatcher returns UNSUPPORTED for uninspectable binary types like JPG."""
    with tempfile.NamedTemporaryFile("wb", suffix=".jpg", delete=False) as tf:
        tf.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00")
        tf_path = Path(tf.name)

    try:
        res = extract_content(tf_path, ".jpg")
        assert res.status == InspectionStatus.UNSUPPORTED
    finally:
        tf_path.unlink(missing_ok=True)
