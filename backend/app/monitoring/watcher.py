"""Filesystem Watcher & Event Handler Module for SentinelDLP (Phase 4).

Wraps watchdog Observer with custom handler logic, deduplication, path validation,
bounded event queuing, and operational session telemetry.
"""

from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Callable, Optional
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from app.core.logging import logger
from app.db.session import SessionLocal
from app.models.monitoring import MonitoringSession
from app.monitoring.deduplication import EventDeduplicator
from app.monitoring.event_normalizer import normalize_watchdog_event
from app.monitoring.event_processor import EventProcessor
from app.monitoring.event_queue import BoundedEventQueue


class SentinelFileSystemEventHandler(FileSystemEventHandler):
    """Event handler forwarding raw watchdog events to normalizer and deduplicator."""

    def __init__(
        self,
        root_id: str,
        canonical_root: Path,
        event_queue: BoundedEventQueue,
        deduplicator: EventDeduplicator,
        session_id: str,
    ) -> None:
        super().__init__()
        self.root_id = root_id
        self.canonical_root = canonical_root
        self.queue = event_queue
        self.deduplicator = deduplicator
        self.session_id = session_id
        self._raw_count = 0
        self._dedup_count = 0
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        """Handle any observed filesystem event."""
        norm_event = normalize_watchdog_event(
            event=event,
            root_id=self.root_id,
            canonical_root=self.canonical_root,
        )
        if not norm_event:
            return

        with self._lock:
            self._raw_count += 1

        # Check deduplication
        if not self.deduplicator.should_process(norm_event):
            with self._lock:
                self._dedup_count += 1
            return

        # Enqueue for background processing
        enqueued = self.queue.enqueue(norm_event)
        if not enqueued:
            logger.warning(f"Failed to enqueue event {norm_event.event_type} (queue saturated)")

    @property
    def raw_count(self) -> int:
        with self._lock:
            return self._raw_count

    @property
    def dedup_count(self) -> int:
        with self._lock:
            return self._dedup_count


class MonitoringWatcher:
    """Manages an individual active filesystem observer and its processing pipeline."""

    def __init__(
        self,
        root_id: str,
        canonical_root: Path,
        session_id: str,
        recursive: bool = True,
    ) -> None:
        self.root_id = root_id
        self.canonical_root = canonical_root
        self.session_id = session_id
        self.recursive = recursive

        self.queue = BoundedEventQueue(maxsize=5000)
        self.deduplicator = EventDeduplicator(debounce_seconds=0.4)
        self.processor = EventProcessor(
            event_queue=self.queue,
            session_id=self.session_id,
            root_id=self.root_id,
            canonical_root=self.canonical_root,
        )
        self.handler = SentinelFileSystemEventHandler(
            root_id=self.root_id,
            canonical_root=self.canonical_root,
            event_queue=self.queue,
            deduplicator=self.deduplicator,
            session_id=self.session_id,
        )

        self._observer: Optional[Observer] = None
        self._status = "configured"
        self._started_at: Optional[datetime] = None
        self._stopped_at: Optional[datetime] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start observer and background processor."""
        with self._lock:
            if self._status == "active":
                return

            self._status = "starting"
            self.processor.start()

            self._observer = Observer()
            self._observer.schedule(
                self.handler,
                str(self.canonical_root),
                recursive=self.recursive,
            )
            self._observer.daemon = True
            self._observer.start()

            self._started_at = datetime.now(timezone.utc)
            self._status = "active"

            # Update DB session
            with SessionLocal() as db:
                sess = db.query(MonitoringSession).filter(MonitoringSession.id == self.session_id).first()
                if sess:
                    sess.status = "active"
                    sess.started_at = self._started_at
                    db.commit()

            logger.info(f"Watcher started for root '{self.root_id}' on {self.canonical_root} (recursive={self.recursive})")

    def stop(self) -> None:
        """Gracefully stop observer, drain queue, and stop processor."""
        with self._lock:
            if self._status in ("stopped", "stopping"):
                return

            self._status = "stopping"

            if self._observer and self._observer.is_alive():
                self._observer.stop()
                self._observer.join(timeout=3.0)

            self.processor.stop(timeout=2.0)
            self.deduplicator.clear()

            self._stopped_at = datetime.now(timezone.utc)
            self._status = "stopped"

            # Update DB session metrics
            with SessionLocal() as db:
                sess = db.query(MonitoringSession).filter(MonitoringSession.id == self.session_id).first()
                if sess:
                    sess.status = "stopped"
                    sess.stopped_at = self._stopped_at
                    sess.raw_event_count = self.handler.raw_count
                    sess.deduplicated_count = self.handler.dedup_count
                    sess.queue_overflow_count = self.queue.overflow_count
                    db.commit()

            logger.info(f"Watcher stopped for root '{self.root_id}'")

    @property
    def status(self) -> str:
        with self._lock:
            if self.queue.overflow_count > 0:
                return "degraded"
            return self._status

    @property
    def started_at(self) -> Optional[datetime]:
        return self._started_at

    @property
    def stopped_at(self) -> Optional[datetime]:
        return self._stopped_at

    def add_sse_listener(self, callback: Callable[[dict], None]) -> None:
        self.processor.add_sse_listener(callback)

    def remove_sse_listener(self, callback: Callable[[dict], None]) -> None:
        self.processor.remove_sse_listener(callback)
