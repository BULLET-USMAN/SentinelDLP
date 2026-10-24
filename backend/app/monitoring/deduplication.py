"""Event Deduplication & Debouncing Module for SentinelDLP (Phase 4).

Mitigates filesystem notification storms (e.g. multi-write operations during save)
while guaranteeing that state-changing events (CREATE, DELETE, RENAME) are preserved.
"""

from datetime import datetime, timezone
import threading
import time
from typing import Dict, Tuple
from app.monitoring.event_normalizer import NormalizedEvent


class EventDeduplicator:
    """Thread-safe deduplicator tracking recent event timestamps per path and event type."""

    def __init__(self, debounce_seconds: float = 0.5) -> None:
        self.debounce_seconds = debounce_seconds
        # Key: (root_id, relative_path, event_type) -> timestamp float
        self._recent_events: Dict[Tuple[str, str, str], float] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def should_process(self, event: NormalizedEvent) -> bool:
        """Evaluate if an event should be processed or suppressed as a duplicate burst.

        Returns:
            True: Event is distinct and should be processed.
            False: Event is a redundant duplicate within the debounce window.
        """
        now = time.time()
        key = (event.root_id, event.relative_path, event.event_type)

        with self._lock:
            # Periodic cleanup of expired cache entries every 10 seconds
            if now - self._last_cleanup > 10.0:
                self._cleanup_expired(now)

            last_time = self._recent_events.get(key)

            # Debouncing logic:
            # For MODIFIED events, suppress if received within debounce window
            if event.event_type in ("FILE_MODIFIED", "DIRECTORY_MODIFIED"):
                if last_time is not None and (now - last_time) < self.debounce_seconds:
                    # Update timestamp to push out the window for trailing writes
                    self._recent_events[key] = now
                    return False

            # For CREATE, DELETE, RENAME, MOVED: Always preserve unless identical event within < 100ms
            elif last_time is not None and (now - last_time) < 0.1:
                return False

            self._recent_events[key] = now
            return True

    def _cleanup_expired(self, current_time: float) -> None:
        """Evict stale keys older than 2x the debounce window."""
        cutoff = current_time - (self.debounce_seconds * 2.0)
        expired_keys = [k for k, t in self._recent_events.items() if t < cutoff]
        for k in expired_keys:
            self._recent_events.pop(k, None)
        self._last_cleanup = current_time

    def clear(self) -> None:
        """Reset deduplication cache."""
        with self._lock:
            self._recent_events.clear()
