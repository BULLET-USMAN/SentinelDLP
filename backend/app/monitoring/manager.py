"""Monitoring Lifecycle Manager for SentinelDLP (Phase 4).

Coordinates active filesystem watchers across authorized directories,
enforces duplicate prevention, and ensures clean lifecycle transitions.
"""

from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Callable, Dict, List, Optional
import uuid
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.models.monitoring import MonitoringConfiguration, MonitoringSession
from app.monitoring.schemas import MonitoringStatusResponse
from app.monitoring.watcher import MonitoringWatcher
from app.scanner.validators import SecurityBoundaryException, get_authorized_root_info


class MonitoringManager:
    """Singleton manager controlling active monitoring watcher lifecycles."""

    def __init__(self) -> None:
        self._watchers: Dict[str, MonitoringWatcher] = {}
        self._lock = threading.Lock()

    def start_monitoring(self, root_id: str, recursive: bool = True) -> MonitoringStatusResponse:
        """Start real-time monitoring for an authorized directory root."""
        # 1. Validate that root_id is in administrator allowlist
        root_name, canonical_path = get_authorized_root_info(root_id)

        with self._lock:
            existing = self._watchers.get(root_id)
            if existing and existing.status in ("active", "starting"):
                # Already running
                return self._build_status_response(existing)

            session_id = str(uuid.uuid4())

            # Create session in DB
            with SessionLocal() as db:
                session = MonitoringSession(
                    id=session_id,
                    root_id=root_id,
                    status="starting",
                    started_at=datetime.now(timezone.utc),
                )
                db.add(session)

                # Upsert configuration
                cfg = db.query(MonitoringConfiguration).filter(MonitoringConfiguration.root_id == root_id).first()
                if not cfg:
                    cfg = MonitoringConfiguration(
                        id=str(uuid.uuid4()),
                        root_id=root_id,
                        root_path=str(canonical_path),
                        enabled=True,
                        recursive=recursive,
                    )
                    db.add(cfg)
                else:
                    cfg.enabled = True
                    cfg.recursive = recursive
                    cfg.root_path = str(canonical_path)

                db.commit()

            watcher = MonitoringWatcher(
                root_id=root_id,
                canonical_root=canonical_path,
                session_id=session_id,
                recursive=recursive,
            )
            watcher.start()
            self._watchers[root_id] = watcher

            logger.info(
                f"Monitoring initiated on root '{root_id}' ({canonical_path}) [session={session_id}]",
                extra={"event": "monitoring_started", "root_id": root_id, "session_id": session_id},
            )
            return self._build_status_response(watcher)

    def stop_monitoring(self, root_id: str) -> Optional[MonitoringStatusResponse]:
        """Stop monitoring an authorized directory root."""
        with self._lock:
            watcher = self._watchers.get(root_id)
            if not watcher:
                return None

            watcher.stop()
            status_resp = self._build_status_response(watcher)
            self._watchers.pop(root_id, None)

            # Update DB configuration
            with SessionLocal() as db:
                cfg = db.query(MonitoringConfiguration).filter(MonitoringConfiguration.root_id == root_id).first()
                if cfg:
                    cfg.enabled = False
                    db.commit()

            logger.info(
                f"Monitoring terminated on root '{root_id}'",
                extra={"event": "monitoring_stopped", "root_id": root_id},
            )
            return status_resp

    def stop_all(self) -> None:
        """Gracefully stop all active watchers during application shutdown."""
        with self._lock:
            root_ids = list(self._watchers.keys())

        for r_id in root_ids:
            try:
                self.stop_monitoring(r_id)
            except Exception as err:
                logger.error(f"Error stopping watcher for root '{r_id}': {str(err)}")

    def get_status(self, root_id: str) -> MonitoringStatusResponse:
        """Get live or historical monitoring status for a root."""
        with self._lock:
            watcher = self._watchers.get(root_id)
            if watcher:
                return self._build_status_response(watcher)

        # Fallback to DB latest session
        with SessionLocal() as db:
            sess = (
                db.query(MonitoringSession)
                .filter(MonitoringSession.root_id == root_id)
                .order_by(MonitoringSession.started_at.desc())
                .first()
            )
            if sess:
                return MonitoringStatusResponse(
                    root_id=root_id,
                    status=sess.status,
                    session_id=sess.id,
                    started_at=sess.started_at,
                    stopped_at=sess.stopped_at,
                    raw_event_count=sess.raw_event_count,
                    processed_event_count=sess.processed_event_count,
                    deduplicated_count=sess.deduplicated_count,
                    queue_overflow_count=sess.queue_overflow_count,
                    last_event_at=sess.last_event_at,
                    last_error=sess.last_error,
                )

        return MonitoringStatusResponse(
            root_id=root_id,
            status="stopped",
        )

    def is_active(self, root_id: str) -> bool:
        """Check if root currently has an active watcher running."""
        with self._lock:
            watcher = self._watchers.get(root_id)
            return bool(watcher and watcher.status == "active")

    def get_active_session_id(self, root_id: str) -> Optional[str]:
        """Get session ID for active watcher."""
        with self._lock:
            watcher = self._watchers.get(root_id)
            return watcher.session_id if watcher else None

    def add_sse_listener(self, root_id: str, callback: Callable[[dict], None]) -> None:
        with self._lock:
            watcher = self._watchers.get(root_id)
        if watcher:
            watcher.add_sse_listener(callback)

    def remove_sse_listener(self, root_id: str, callback: Callable[[dict], None]) -> None:
        with self._lock:
            watcher = self._watchers.get(root_id)
        if watcher:
            watcher.remove_sse_listener(callback)

    def _build_status_response(self, watcher: MonitoringWatcher) -> MonitoringStatusResponse:
        """Helper to construct status schema from watcher and DB session."""
        with SessionLocal() as db:
            sess = db.query(MonitoringSession).filter(MonitoringSession.id == watcher.session_id).first()
            processed = sess.processed_event_count if sess else 0
            last_event = sess.last_event_at if sess else None

        return MonitoringStatusResponse(
            root_id=watcher.root_id,
            status=watcher.status,
            session_id=watcher.session_id,
            started_at=watcher.started_at,
            stopped_at=watcher.stopped_at,
            raw_event_count=watcher.handler.raw_count,
            processed_event_count=processed,
            deduplicated_count=watcher.handler.dedup_count,
            queue_overflow_count=watcher.queue.overflow_count,
            last_event_at=last_event,
        )


# Singleton monitoring manager instance
monitoring_manager = MonitoringManager()
