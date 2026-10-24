"""Unit Tests for Monitoring Subsystem Components (Phase 4).

Validates:
- Event normalization across creation, modification, deletion, rename, and movement
- Event deduplication and debounce suppression
- Bounded event queue capacity, backpressure, and overflow tracking
- Canonical path boundary checks
"""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import time
import pytest
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)
from app.monitoring.deduplication import EventDeduplicator
from app.monitoring.event_normalizer import (
    NormalizedEvent,
    normalize_watchdog_event,
)
from app.monitoring.event_queue import BoundedEventQueue


def test_normalize_file_created_event() -> None:
    """Verify normalization of FileCreatedEvent within authorized root."""
    canonical_root = Path("C:/data/samples").resolve()
    file_path = canonical_root / "subdir" / "new_policy.txt"

    raw_event = FileCreatedEvent(str(file_path))
    norm = normalize_watchdog_event(
        event=raw_event,
        root_id="synthetic_samples",
        canonical_root=canonical_root,
    )

    assert norm is not None
    assert norm.event_type == "FILE_CREATED"
    assert norm.is_directory is False
    assert norm.relative_path == "subdir/new_policy.txt"
    assert norm.root_id == "synthetic_samples"
    assert norm.previous_relative_path is None


def test_normalize_file_rename_vs_move() -> None:
    """Verify that moving within same directory is RENAMED, across dirs is MOVED."""
    canonical_root = Path("C:/data/samples").resolve()

    # 1. Same parent folder = RENAME
    src_rename = canonical_root / "docs" / "old_name.txt"
    dest_rename = canonical_root / "docs" / "new_name.txt"
    raw_rename = FileMovedEvent(str(src_rename), str(dest_rename))

    norm_rename = normalize_watchdog_event(raw_rename, "samples", canonical_root)
    assert norm_rename is not None
    assert norm_rename.event_type == "FILE_RENAMED"
    assert norm_rename.relative_path == "docs/new_name.txt"
    assert norm_rename.previous_relative_path == "docs/old_name.txt"

    # 2. Different parent folder = MOVED
    src_move = canonical_root / "docs" / "file.txt"
    dest_move = canonical_root / "archive" / "file.txt"
    raw_move = FileMovedEvent(str(src_move), str(dest_move))

    norm_move = normalize_watchdog_event(raw_move, "samples", canonical_root)
    assert norm_move is not None
    assert norm_move.event_type == "FILE_MOVED"
    assert norm_move.relative_path == "archive/file.txt"
    assert norm_move.previous_relative_path == "docs/file.txt"


def test_normalize_unauthorized_path_rejection() -> None:
    """Verify events outside the authorized canonical root return None."""
    canonical_root = Path("C:/data/samples").resolve()
    outside_file = Path("C:/Windows/System32/evil.dll")

    raw_event = FileCreatedEvent(str(outside_file))
    norm = normalize_watchdog_event(raw_event, "samples", canonical_root)
    assert norm is None


def test_event_deduplication_debounce_suppression() -> None:
    """Verify duplicate MODIFIED bursts within debounce window are suppressed."""
    deduplicator = EventDeduplicator(debounce_seconds=0.3)
    canonical_root = Path("C:/data/samples").resolve()
    test_path = canonical_root / "document.txt"

    event1 = NormalizedEvent(
        event_id="e1",
        root_id="samples",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="document.txt",
        previous_relative_path=None,
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        absolute_path=test_path,
    )

    event2 = NormalizedEvent(
        event_id="e2",
        root_id="samples",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="document.txt",
        previous_relative_path=None,
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        absolute_path=test_path,
    )

    # First event should pass
    assert deduplicator.should_process(event1) is True
    # Immediate second modified event should be suppressed (debounced)
    assert deduplicator.should_process(event2) is False

    # After debounce window expires, new event passes
    time.sleep(0.35)
    assert deduplicator.should_process(event2) is True


def test_bounded_queue_overflow_tracking() -> None:
    """Verify bounded queue rejects excess items and records overflow metric."""
    q = BoundedEventQueue(maxsize=3)
    canonical_root = Path("C:/data/samples").resolve()

    def make_event(idx: int) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=f"ev-{idx}",
            root_id="samples",
            event_type="FILE_MODIFIED",
            is_directory=False,
            relative_path=f"file_{idx}.txt",
            previous_relative_path=None,
            occurred_at=datetime.now(timezone.utc),
            collected_at=datetime.now(timezone.utc),
            absolute_path=canonical_root / f"file_{idx}.txt",
        )

    # Enqueue up to capacity
    assert q.enqueue(make_event(1)) is True
    assert q.enqueue(make_event(2)) is True
    assert q.enqueue(make_event(3)) is True

    # 4th item overflows
    assert q.enqueue(make_event(4)) is False
    assert q.overflow_count == 1
    assert q.qsize == 3
