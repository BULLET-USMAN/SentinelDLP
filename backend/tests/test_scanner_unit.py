"""Unit Tests for Scanner Discovery, Boundaries, and File Typing (Phase 2)."""

import os
from pathlib import Path
import tempfile
import threading
import pytest
from app.scanner.discovery import ScanCancelledException, discover_files
from app.scanner.filetypes import identify_file_type
from app.scanner.metadata import extract_file_metadata
from app.scanner.validators import validate_path_within_boundary


def test_file_type_identification_supported() -> None:
    """Verify supported formats are properly categorized."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # 1. Valid PDF with magic bytes
        pdf_file = root / "doc.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n...")
        analysis = identify_file_type(pdf_file)
        assert analysis.is_supported is True
        assert analysis.category == "Document"
        assert analysis.type_mismatch is False

        # 2. Python source file
        py_file = root / "script.py"
        py_file.write_text("print('hello')", encoding="utf-8")
        analysis = identify_file_type(py_file)
        assert analysis.is_supported is True
        assert analysis.category == "Source Code"
        assert analysis.type_mismatch is False

        # 3. Valid PNG image
        png_file = root / "image.png"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n...")
        analysis = identify_file_type(png_file)
        assert analysis.is_supported is True
        assert analysis.category == "Image"
        assert analysis.type_mismatch is False


def test_file_type_discrepancy_mismatch_flag() -> None:
    """Verify mismatch flag when extension does not match underlying magic bytes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # Plain text file disguised with a .pdf extension
        spoofed_pdf = root / "fake.pdf"
        spoofed_pdf.write_text("This is plain text disguised as a PDF file.", encoding="utf-8")

        analysis = identify_file_type(spoofed_pdf)
        assert analysis.type_mismatch is True
        assert analysis.file_extension == ".pdf"


def test_empty_directory_scan() -> None:
    """Verify scanning an empty directory yields zero files cleanly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        discovered = list(discover_files(root))
        assert len(discovered) == 0


def test_recursive_discovery_and_exclusion() -> None:
    """Verify recursive directory traversal while respecting exclusion lists."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # Level 1 files
        (root / "root_file.txt").write_text("content", encoding="utf-8")

        # Nested folder
        nested = root / "nested_dir"
        nested.mkdir()
        (nested / "nested_file.csv").write_text("col1,col2\n1,2", encoding="utf-8")

        # Excluded folder (e.g. .git or node_modules)
        excluded = root / "node_modules"
        excluded.mkdir()
        (excluded / "library.js").write_text("module.exports = {}", encoding="utf-8")

        discovered = list(discover_files(root))
        filenames = [f[0].name for f in discovered]

        assert "root_file.txt" in filenames
        assert "nested_file.csv" in filenames
        # Excluded directory contents must be skipped
        assert "library.js" not in filenames


def test_boundary_validation_defense() -> None:
    """Verify traversal outside root is rejected."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir) / "safe_root"
        root.mkdir()
        outside_dir = Path(tmp_dir) / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        # Path within safe root
        safe_file = root / "safe.txt"
        safe_file.write_text("safe", encoding="utf-8")

        valid, _ = validate_path_within_boundary(safe_file, root)
        assert valid is True

        # Outside file checked against safe_root boundary
        invalid, err = validate_path_within_boundary(outside_file, root)
        assert invalid is False
        assert "Path traversal detected" in err


def test_scan_cancellation_signal() -> None:
    """Verify setting cancellation token halts discovery immediately."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        for i in range(10):
            (root / f"file_{i}.txt").write_text(f"content {i}", encoding="utf-8")

        cancel_event = threading.Event()
        cancel_event.set()  # Signal cancellation prior to or during scan

        with pytest.raises(ScanCancelledException):
            list(discover_files(root, cancellation_event=cancel_event))


def test_metadata_extraction_timestamps_and_relative_path() -> None:
    """Verify relative path and timestamp extraction."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        sub = root / "sub_folder"
        sub.mkdir()
        target = sub / "data.json"
        target.write_text('{"key": "value"}', encoding="utf-8")

        meta = extract_file_metadata(target, root_path=root, compute_hash=True)
        assert meta.filename == "data.json"
        assert meta.relative_path == "sub_folder/data.json"
        assert meta.file_extension == ".json"
        assert meta.size_bytes > 0
        assert meta.sha256_hash is not None
        assert meta.modified_at is not None
        assert meta.status == "scanned"
