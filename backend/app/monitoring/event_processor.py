"""Event Processor Module for SentinelDLP (Phase 4).

Consumes normalized activity events, updates Phase 2 file inventory records,
triggers Phase 3 sensitive data classification on created/modified files,
persists auditable events in PostgreSQL, and broadcasts live telemetry.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time
from typing import Callable, List, Optional, Set
import uuid
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.detection.classification import POLICY_VERSION
from app.detection.engine import detection_engine
from app.detection.rules import DetectionCategory, SensitivityLevel
from app.models.detection import DetectionFinding, FileClassification
from app.models.monitoring import FileActivityEvent, MonitoringSession
from app.models.scanner import ScanJob, ScannedFile
from app.monitoring.event_normalizer import NormalizedEvent
from app.monitoring.event_queue import BoundedEventQueue
from app.monitoring.schemas import FileActivityEventItem
from app.scanner.metadata import extract_file_metadata


class EventProcessor:
    """Processes normalized events from the queue in a dedicated background worker thread."""

    def __init__(
        self,
        event_queue: BoundedEventQueue,
        session_id: str,
        root_id: str,
        canonical_root: Path,
        excluded_patterns: Optional[Set[str]] = None,
    ) -> None:
        self.queue = event_queue
        self.session_id = session_id
        self.root_id = root_id
        self.canonical_root = canonical_root
        self.excluded_patterns = excluded_patterns or set(settings.EXCLUDED_DIR_NAMES)

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._sse_listeners: List[Callable[[dict], None]] = []
        self._listener_lock = threading.Lock()

    def start(self) -> None:
        """Start the background processing worker thread."""
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._process_loop,
            daemon=True,
            name=f"MonitoringProcessor-{self.root_id}",
        )
        self._worker_thread.start()
        logger.info(f"Started EventProcessor worker for root '{self.root_id}'")

    def stop(self, timeout: float = 3.0) -> None:
        """Signal worker to stop and wait for completion."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        logger.info(f"Stopped EventProcessor worker for root '{self.root_id}'")

    def add_sse_listener(self, callback: Callable[[dict], None]) -> None:
        """Register an SSE subscriber callback."""
        with self._listener_lock:
            self._sse_listeners.append(callback)

    def remove_sse_listener(self, callback: Callable[[dict], None]) -> None:
        """Unregister an SSE subscriber callback."""
        with self._listener_lock:
            if callback in self._sse_listeners:
                self._sse_listeners.remove(callback)

    def _broadcast_sse(self, event_data: dict) -> None:
        """Deliver event payload to all active SSE streaming subscribers."""
        with self._listener_lock:
            listeners = list(self._sse_listeners)

        for listener in listeners:
            try:
                listener(event_data)
            except Exception:
                pass

    def _process_loop(self) -> None:
        """Continuous event consumption loop."""
        while not self._stop_event.is_set():
            event = self.queue.dequeue(timeout=0.5)
            if event is None:
                continue

            try:
                self._handle_single_event(event)
            except Exception as err:
                logger.error(
                    f"Unexpected error processing event {event.event_id} ({event.event_type}): {str(err)}",
                    exc_info=True,
                    extra={"event": "monitoring_processing_error", "event_id": event.event_id},
                )
            finally:
                self.queue.task_done()

    def _handle_single_event(self, event: NormalizedEvent) -> None:
        """Process an individual event with path verification, classification, and persistence."""
        # 1. Path & boundary validation
        if not self._is_path_permitted(event.relative_path):
            self._persist_event_record(
                event=event,
                status="ignored",
                error_category="excluded_path_filter",
            )
            return

        # 2. Handle directory events
        if event.is_directory:
            self._persist_event_record(event=event, status="processed")
            return

        # 3. Handle file events
        if event.event_type in ("FILE_CREATED", "FILE_MODIFIED", "FILE_MOVED", "FILE_RENAMED"):
            self._handle_file_create_or_modify(event)
        elif event.event_type == "FILE_DELETED":
            self._handle_file_deletion(event)
        else:
            self._persist_event_record(event=event, status="processed")

    def _handle_file_create_or_modify(self, event: NormalizedEvent) -> None:
        """Extract metadata, compute hash, classify sensitivity, and persist."""
        target_path = event.absolute_path

        # Small settling pause for active multi-write file locks
        time.sleep(0.05)

        if not target_path.exists() or not target_path.is_file():
            # File was transient (e.g., atomic rename or deleted immediately)
            self._persist_event_record(
                event=event,
                status="processed",
                error_category="file_transient_or_unreadable",
            )
            return

        # Extract Phase 2 metadata & hash
        meta = extract_file_metadata(
            file_path=target_path,
            root_path=self.canonical_root,
            compute_hash=True,
            max_size_bytes=settings.MAX_FILE_SIZE_BYTES,
        )

        # Trigger Phase 3 content extraction and classification
        analysis = detection_engine.inspect_and_classify_file(target_path, meta.file_extension)
        sensitivity_label = analysis.classification.sensitivity_label.value

        # Update database
        with SessionLocal() as db:
            # Upsert or link ScannedFile
            scanned_file = (
                db.query(ScannedFile)
                .filter(ScannedFile.relative_path == event.relative_path)
                .order_by(ScannedFile.scan_timestamp.desc())
                .first()
            )

            file_id = scanned_file.id if scanned_file else str(uuid.uuid4())
            if not scanned_file:
                # Find an existing scan job for this root or ensure a live monitoring job placeholder exists
                latest_job = (
                    db.query(ScanJob)
                    .filter(ScanJob.root_id == self.root_id)
                    .order_by(ScanJob.started_at.desc())
                    .first()
                )
                if latest_job:
                    job_id = latest_job.id
                else:
                    live_job_id = f"live_{self.root_id}"[:36]
                    live_job = db.query(ScanJob).filter(ScanJob.id == live_job_id).first()
                    if not live_job:
                        live_job = ScanJob(
                            id=live_job_id,
                            root_id=self.root_id,
                            root_path=str(self.canonical_root),
                            status="active",
                        )
                        db.add(live_job)
                        db.flush()
                    job_id = live_job.id

                scanned_file = ScannedFile(
                    id=file_id,
                    scan_job_id=job_id,
                    filename=meta.filename,
                    relative_path=event.relative_path,
                    file_extension=meta.file_extension,
                    detected_type=meta.detected_type,
                    size_bytes=meta.size_bytes,
                    created_at=meta.created_at,
                    modified_at=meta.modified_at,
                    sha256_hash=meta.sha256_hash,
                    scan_timestamp=datetime.now(timezone.utc),
                    status=meta.status,
                    type_mismatch=meta.type_mismatch,
                )
                db.add(scanned_file)
            else:
                # Update existing inventory record
                scanned_file.size_bytes = meta.size_bytes
                scanned_file.modified_at = meta.modified_at
                scanned_file.sha256_hash = meta.sha256_hash
                scanned_file.status = meta.status
                scanned_file.type_mismatch = meta.type_mismatch

            # Upsert FileClassification
            existing_class = (
                db.query(FileClassification)
                .filter(FileClassification.scanned_file_id == file_id)
                .first()
            )
            if existing_class:
                existing_class.sensitivity_label = sensitivity_label
                existing_class.policy_version = analysis.classification.policy_version
                existing_class.classified_at = datetime.now(timezone.utc)
                existing_class.inspection_status = analysis.inspection_status.value
                existing_class.explanation = analysis.classification.explanation
                existing_class.highest_confidence = analysis.classification.highest_confidence
            else:
                new_class = FileClassification(
                    id=str(uuid.uuid4()),
                    scanned_file_id=file_id,
                    sensitivity_label=sensitivity_label,
                    policy_version=analysis.classification.policy_version,
                    classified_at=datetime.now(timezone.utc),
                    inspection_status=analysis.inspection_status.value,
                    explanation=analysis.classification.explanation,
                    highest_confidence=analysis.classification.highest_confidence,
                )
                db.add(new_class)

            # Persist findings (clean old findings for this file first)
            db.query(DetectionFinding).filter(DetectionFinding.scanned_file_id == file_id).delete()
            for finding in analysis.findings:
                f_record = DetectionFinding(
                    id=str(uuid.uuid4()),
                    scanned_file_id=file_id,
                    rule_id=finding.rule_id,
                    rule_version="1.0.0",
                    category=finding.category.value,
                    confidence=finding.confidence.value,
                    occurrence_count=finding.occurrence_count,
                    detected_at=datetime.now(timezone.utc),
                )
                db.add(f_record)

            # Persist FileActivityEvent record
            event_record = FileActivityEvent(
                id=event.event_id,
                root_id=event.root_id,
                event_type=event.event_type,
                is_directory=False,
                relative_path=event.relative_path,
                previous_relative_path=event.previous_relative_path,
                occurred_at=event.occurred_at,
                collected_at=event.collected_at,
                processed_at=datetime.now(timezone.utc),
                status="processed",
                associated_file_id=file_id,
                sensitivity_label=sensitivity_label,
                file_type=meta.detected_type,
                size_bytes=meta.size_bytes,
                sha256_hash=meta.sha256_hash,
                event_source="watchdog",
            )
            db.add(event_record)

            # Update session metrics
            session = db.query(MonitoringSession).filter(MonitoringSession.id == self.session_id).first()
            if session:
                session.processed_event_count += 1
                session.last_event_at = datetime.now(timezone.utc)

            db.commit()

        # Broadcast live SSE update
        self._broadcast_event(event_record)

    def _handle_file_deletion(self, event: NormalizedEvent) -> None:
        """Handle file deletion by marking inventory status and recording event."""
        with SessionLocal() as db:
            scanned_file = (
                db.query(ScannedFile)
                .filter(ScannedFile.relative_path == event.relative_path)
                .order_by(ScannedFile.scan_timestamp.desc())
                .first()
            )

            file_id = None
            cached_label = None
            if scanned_file:
                file_id = scanned_file.id
                scanned_file.status = "deleted"
                # Check previous classification
                prev_class = (
                    db.query(FileClassification)
                    .filter(FileClassification.scanned_file_id == file_id)
                    .first()
                )
                if prev_class:
                    cached_label = prev_class.sensitivity_label

            event_record = FileActivityEvent(
                id=event.event_id,
                root_id=event.root_id,
                event_type=event.event_type,
                is_directory=False,
                relative_path=event.relative_path,
                previous_relative_path=None,
                occurred_at=event.occurred_at,
                collected_at=event.collected_at,
                processed_at=datetime.now(timezone.utc),
                status="processed",
                associated_file_id=file_id,
                sensitivity_label=cached_label,
                event_source="watchdog",
            )
            db.add(event_record)

            session = db.query(MonitoringSession).filter(MonitoringSession.id == self.session_id).first()
            if session:
                session.processed_event_count += 1
                session.last_event_at = datetime.now(timezone.utc)

            db.commit()

        self._broadcast_event(event_record)

    def _persist_event_record(
        self,
        event: NormalizedEvent,
        status: str,
        error_category: Optional[str] = None,
    ) -> None:
        """Persist generic or ignored event record."""
        with SessionLocal() as db:
            event_record = FileActivityEvent(
                id=event.event_id,
                root_id=event.root_id,
                event_type=event.event_type,
                is_directory=event.is_directory,
                relative_path=event.relative_path,
                previous_relative_path=event.previous_relative_path,
                occurred_at=event.occurred_at,
                collected_at=event.collected_at,
                processed_at=datetime.now(timezone.utc),
                status=status,
                event_source="watchdog",
                error_category=error_category,
            )
            db.add(event_record)

            session = db.query(MonitoringSession).filter(MonitoringSession.id == self.session_id).first()
            if session:
                session.processed_event_count += 1
                session.last_event_at = datetime.now(timezone.utc)

            db.commit()

        self._broadcast_event(event_record)

    def _broadcast_event(self, record: FileActivityEvent) -> None:
        """Format and broadcast event payload to SSE listeners."""
        payload = {
            "id": record.id,
            "root_id": record.root_id,
            "event_type": record.event_type,
            "is_directory": record.is_directory,
            "relative_path": record.relative_path,
            "previous_relative_path": record.previous_relative_path,
            "occurred_at": record.occurred_at.isoformat() if record.occurred_at else None,
            "status": record.status,
            "sensitivity_label": record.sensitivity_label,
            "file_type": record.file_type,
            "size_bytes": record.size_bytes,
            "sha256_hash": record.sha256_hash,
            "event_source": record.event_source,
        }
        self._broadcast_sse(payload)

    def _is_path_permitted(self, relative_path: str) -> bool:
        """Check if path is excluded by system boundaries."""
        parts = Path(relative_path).parts
        for part in parts:
            if part in self.excluded_patterns:
                return False
            if part.startswith(".") and part != ".":
                # Allow .env files or .gitignore, but exclude hidden system dirs
                if part not in (".env", ".env.example", ".gitignore"):
                    return False
        return True
