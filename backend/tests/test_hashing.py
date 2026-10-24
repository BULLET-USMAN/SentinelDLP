"""Unit Tests for Streaming SHA-256 Hashing in SentinelDLP (Phase 2).

Tests standard test vectors, chunking integrity, large-file thresholds,
and graceful handling of deleted/inaccessible files.
"""

from pathlib import Path
import tempfile
import pytest
from app.scanner.hashing import calculate_sha256

# Standard Known Test Vectors
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# "The quick brown fox jumps over the lazy dog"
FOX_STRING = b"The quick brown fox jumps over the lazy dog"
FOX_SHA256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"


def test_empty_file_hash() -> None:
    """Verify SHA-256 digest of an empty file matches canonical standard."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        temp_path = Path(tf.name)

    try:
        digest, bytes_read, err = calculate_sha256(temp_path)
        assert err is None
        assert bytes_read == 0
        assert digest == EMPTY_SHA256
    finally:
        temp_path.unlink(missing_ok=True)


def test_known_vector_hash() -> None:
    """Verify SHA-256 calculation matches known cryptographic test vector."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(FOX_STRING)
        temp_path = Path(tf.name)

    try:
        digest, bytes_read, err = calculate_sha256(temp_path)
        assert err is None
        assert bytes_read == len(FOX_STRING)
        assert digest == FOX_SHA256
    finally:
        temp_path.unlink(missing_ok=True)


def test_chunked_streaming_hashing() -> None:
    """Verify chunked streaming reads accurately hash payloads larger than chunk size."""
    payload = b"A" * (65536 * 3 + 128)  # 3+ chunks of 64KB
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(payload)
        temp_path = Path(tf.name)

    try:
        # Use small chunk size (1024 bytes) to force multiple iterations
        digest, bytes_read, err = calculate_sha256(temp_path, chunk_size=1024)
        assert err is None
        assert bytes_read == len(payload)
        assert len(digest) == 64
    finally:
        temp_path.unlink(missing_ok=True)


def test_max_file_size_exceeded() -> None:
    """Verify files exceeding max_size_bytes are safely skipped without hashing."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"X" * 1024)
        temp_path = Path(tf.name)

    try:
        # Set max_size to 500 bytes (file is 1024 bytes)
        digest, bytes_read, err = calculate_sha256(temp_path, max_size=500)
        assert digest is None
        assert bytes_read == 0
        assert "exceeds limit" in err
    finally:
        temp_path.unlink(missing_ok=True)


def test_file_disappeared_graceful_handling() -> None:
    """Verify non-existent or deleted file produces a structured error instead of crashing."""
    non_existent = Path(tempfile.gettempdir()) / "non_existent_sentinel_file.tmp"
    if non_existent.exists():
        non_existent.unlink()

    digest, bytes_read, err = calculate_sha256(non_existent)
    assert digest is None
    assert bytes_read == 0
    assert "disappeared" in err or "deleted" in err
