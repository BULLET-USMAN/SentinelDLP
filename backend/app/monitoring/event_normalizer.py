"""Event Normalization Module for SentinelDLP (Phase 4).

Converts platform-specific watchdog filesystem notifications into canonical,
structured application events while enforcing path boundaries and UTC timestamps.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Optional
import uuid
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
)


@dataclass
class NormalizedEvent:
    """Canonical application event representing an observed filesystem change."""

    event_id: str
    root_id: str
    event_type: str
    is_directory: bool
    relative_path: str
    previous_relative_path: Optional[str]
    occurred_at: datetime
    collected_at: datetime
    absolute_path: Path
    previous_absolute_path: Optional[Path] = None


def normalize_watchdog_event(
    event: FileSystemEvent,
    root_id: str,
    canonical_root: Path,
) -> Optional[NormalizedEvent]:
    """Convert raw watchdog FileSystemEvent into a NormalizedEvent.

    Returns None if the event should be discarded (e.g. root dir itself or unparsable path).
    """
    now = datetime.now(timezone.utc)
    event_id = str(uuid.uuid4())
    is_dir = getattr(event, "is_directory", False)

    src_path_str = getattr(event, "src_path", "")
    if not src_path_str:
        return None

    src_path = Path(src_path_str).resolve()

    # Skip events for the root directory itself
    if src_path == canonical_root:
        return None

    # Determine event type and relative paths
    if isinstance(event, (FileMovedEvent, DirMovedEvent)):
        dest_path_str = getattr(event, "dest_path", "")
        dest_path = Path(dest_path_str).resolve() if dest_path_str else None

        # Check if src and dest are within canonical_root
        src_inside = _is_within_root(src_path, canonical_root)
        dest_inside = _is_within_root(dest_path, canonical_root) if dest_path else False

        if src_inside and dest_inside and dest_path:
            # File moved or renamed within the authorized root
            prev_rel = _get_relative_path(src_path, canonical_root)
            curr_rel = _get_relative_path(dest_path, canonical_root)

            # Determine whether it is a rename (same parent) or move (different folder)
            is_rename = src_path.parent == dest_path.parent
            if is_dir:
                ev_type = "DIRECTORY_RENAMED" if is_rename else "DIRECTORY_MOVED"
            else:
                ev_type = "FILE_RENAMED" if is_rename else "FILE_MOVED"

            return NormalizedEvent(
                event_id=event_id,
                root_id=root_id,
                event_type=ev_type,
                is_directory=is_dir,
                relative_path=curr_rel,
                previous_relative_path=prev_rel,
                occurred_at=now,
                collected_at=now,
                absolute_path=dest_path,
                previous_absolute_path=src_path,
            )
        elif src_inside and not dest_inside:
            # Moved out of root -> treat as DELETED from monitored root perspective
            rel_path = _get_relative_path(src_path, canonical_root)
            ev_type = "DIRECTORY_DELETED" if is_dir else "FILE_DELETED"
            return NormalizedEvent(
                event_id=event_id,
                root_id=root_id,
                event_type=ev_type,
                is_directory=is_dir,
                relative_path=rel_path,
                previous_relative_path=None,
                occurred_at=now,
                collected_at=now,
                absolute_path=src_path,
            )
        elif not src_inside and dest_inside and dest_path:
            # Moved into root from outside -> treat as CREATED inside monitored root
            rel_path = _get_relative_path(dest_path, canonical_root)
            ev_type = "DIRECTORY_CREATED" if is_dir else "FILE_CREATED"
            return NormalizedEvent(
                event_id=event_id,
                root_id=root_id,
                event_type=ev_type,
                is_directory=is_dir,
                relative_path=rel_path,
                previous_relative_path="[external]",
                occurred_at=now,
                collected_at=now,
                absolute_path=dest_path,
            )
        else:
            # Neither in root
            return None

    # Handle standard Create, Modify, Delete
    if not _is_within_root(src_path, canonical_root):
        return None

    rel_path = _get_relative_path(src_path, canonical_root)

    if isinstance(event, FileCreatedEvent):
        ev_type = "FILE_CREATED"
    elif isinstance(event, FileModifiedEvent):
        ev_type = "FILE_MODIFIED"
    elif isinstance(event, FileDeletedEvent):
        ev_type = "FILE_DELETED"
    elif isinstance(event, DirCreatedEvent):
        ev_type = "DIRECTORY_CREATED"
    elif isinstance(event, DirModifiedEvent):
        ev_type = "DIRECTORY_MODIFIED"
    elif isinstance(event, DirDeletedEvent):
        ev_type = "DIRECTORY_DELETED"
    else:
        # Fallback for generic event
        ev_type = "FILE_MODIFIED" if not is_dir else "DIRECTORY_MODIFIED"

    return NormalizedEvent(
        event_id=event_id,
        root_id=root_id,
        event_type=ev_type,
        is_directory=is_dir,
        relative_path=rel_path,
        previous_relative_path=None,
        occurred_at=now,
        collected_at=now,
        absolute_path=src_path,
    )


def _is_within_root(target: Path, canonical_root: Path) -> bool:
    """Verify target path is located strictly within canonical_root."""
    try:
        target.relative_to(canonical_root)
        return True
    except (ValueError, Exception):
        return False


def _get_relative_path(target: Path, canonical_root: Path) -> str:
    """Return standard POSIX relative path string."""
    try:
        rel = target.relative_to(canonical_root)
        return str(rel).replace("\\", "/")
    except Exception:
        return target.name
