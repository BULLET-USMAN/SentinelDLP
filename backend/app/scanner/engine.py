"""Intelligent File Scanning Engine for SentinelDLP (Phase 2).

Coordinates secure file discovery, signature verification, streaming hashing,
and database persistence with real-time cancellation tokens.
"""

from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Dict, Optional
import uuid
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.detection.engine import detection_engine
from app.detection.classification import POLICY_VERSION
from app.detection.extractors import InspectionStatus
from app.detection.rules import DetectionCategory, SensitivityLevel
from app.models.detection import DetectionFinding, FileClassification, ScanDetectionSummary
from app.models.scanner import ScanJob, ScannedFile
from app.scanner.discovery import ScanCancelledException, discover_files
from app.scanner.metadata import extract_file_metadata
from app.scanner.validators import get_authorized_root_info


class ScanEngine:
    """Singleton scan engine managing active background scan jobs."""

    def __init__(self) -> None:
        self._cancellation_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def start_scan_job(self, root_id: str) -> str:
        """Initialize a new scan job and trigger execution in a background worker.

        Returns:
            scan_id: Unique UUID string identifying the job.
        """
        # Validate that root_id is authorized
        root_name, canonical_path = get_authorized_root_info(root_id)
        scan_id = str(uuid.uuid4())

        # Create database record in pending state
        with SessionLocal() as db:
            job = ScanJob(
                id=scan_id,
                root_id=root_id,
                root_path=str(canonical_path),
                status="pending",
                started_at=datetime.now(timezone.utc),
            )
            db.add(job)
            db.commit()

        # Register cancellation event token
        cancellation_event = threading.Event()
        with self._lock:
            self._cancellation_events[scan_id] = cancellation_event

        # Launch bounded background execution thread
        worker_thread = threading.Thread(
            target=self._execute_scan_worker,
            args=(scan_id, canonical_path, cancellation_event),
            daemon=True,
            name=f"ScannerWorker-{scan_id[:8]}",
        )
        worker_thread.start()

        logger.info(
            f"Initiated scan job {scan_id} on root '{root_id}' ({canonical_path})",
            extra={"event": "scan_started", "scan_id": scan_id, "root_id": root_id},
        )
        return scan_id

    def cancel_scan_job(self, scan_id: str) -> bool:
        """Request immediate cancellation of a running scan job.

        Returns:
            bool: True if cancellation token was signaled, False if job not found or not active.
        """
        with self._lock:
            event = self._cancellation_events.get(scan_id)
            if event:
                event.set()
                logger.info(f"Cancellation signaled for scan job {scan_id}", extra={"event": "scan_cancel_requested", "scan_id": scan_id})
                return True
        return False

    def is_scan_active(self, scan_id: str) -> bool:
        """Check if a scan job is currently being processed."""
        with self._lock:
            return scan_id in self._cancellation_events

    def _execute_scan_worker(
        self,
        scan_id: str,
        canonical_root: Path,
        cancellation_event: threading.Event,
    ) -> None:
        """Background execution worker processing discovered files."""
        start_time = time.time()
        discovered_count = 0
        processed_count = 0
        skipped_count = 0
        error_count = 0
        total_bytes = 0
        final_status = "completed"
        error_message = None

        # Phase 3: Aggregated detection metrics
        files_inspected = 0
        sensitive_files_count = 0
        public_count = 0
        internal_count = 0
        confidential_count = 0
        restricted_count = 0
        not_assessed_count = 0
        pii_count = 0
        credential_count = 0
        financial_count = 0
        confidential_label_count = 0

        with SessionLocal() as db:
            # Transition status from pending to running
            job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not job:
                logger.error(f"Scan job {scan_id} not found in database during worker startup")
                return

            job.status = "running"
            db.commit()

            try:
                # Traverse files securely
                file_generator = discover_files(
                    root_path=canonical_root,
                    max_files=settings.MAX_FILES_PER_SCAN,
                    cancellation_event=cancellation_event,
                )

                for file_path, skip_reason in file_generator:
                    # Enforce wall-clock duration limit
                    if (time.time() - start_time) > settings.MAX_SCAN_DURATION_SECONDS:
                        logger.warning(
                            f"Scan job {scan_id} exceeded maximum duration threshold ({settings.MAX_SCAN_DURATION_SECONDS}s). Terminating.",
                            extra={"event": "scan_timeout", "scan_id": scan_id},
                        )
                        final_status = "completed"
                        error_message = f"Scan stopped: exceeded maximum duration limit of {settings.MAX_SCAN_DURATION_SECONDS}s"
                        break

                    discovered_count += 1

                    if skip_reason:
                        # File path boundary or permission issue caught during discovery
                        skipped_count += 1
                        error_count += 1
                        not_assessed_count += 1
                        scanned_record = ScannedFile(
                            id=str(uuid.uuid4()),
                            scan_job_id=scan_id,
                            filename=file_path.name,
                            relative_path=file_path.name,
                            file_extension=file_path.suffix.lower() or "[none]",
                            detected_type="Unknown",
                            size_bytes=0,
                            status="skipped",
                            error_message=skip_reason,
                            scan_timestamp=datetime.now(timezone.utc),
                        )
                        db.add(scanned_record)
                        classification_record = FileClassification(
                            id=str(uuid.uuid4()),
                            scanned_file_id=scanned_record.id,
                            sensitivity_label=SensitivityLevel.NOT_ASSESSED.value,
                            policy_version=POLICY_VERSION,
                            classified_at=datetime.now(timezone.utc),
                            inspection_status="skipped",
                            explanation=f"Skipped during discovery: {skip_reason}",
                            highest_confidence="N/A",
                        )
                        db.add(classification_record)
                        continue

                    # Extract file metadata and hash
                    meta = extract_file_metadata(
                        file_path=file_path,
                        root_path=canonical_root,
                        compute_hash=True,
                        max_size_bytes=settings.MAX_FILE_SIZE_BYTES,
                    )

                    scanned_record = ScannedFile(
                        id=str(uuid.uuid4()),
                        scan_job_id=scan_id,
                        filename=meta.filename,
                        relative_path=meta.relative_path,
                        file_extension=meta.file_extension,
                        detected_type=meta.detected_type,
                        size_bytes=meta.size_bytes,
                        created_at=meta.created_at,
                        modified_at=meta.modified_at,
                        sha256_hash=meta.sha256_hash,
                        scan_timestamp=meta.scan_timestamp,
                        status=meta.status,
                        error_message=meta.error_message,
                        type_mismatch=meta.type_mismatch,
                    )
                    db.add(scanned_record)

                    if meta.status == "scanned":
                        processed_count += 1
                        total_bytes += meta.size_bytes

                        # Phase 3: Content inspection & sensitivity classification
                        analysis = detection_engine.inspect_and_classify_file(file_path, meta.file_extension)
                        if analysis.inspection_status in (InspectionStatus.INSPECTED, InspectionStatus.PARTIAL):
                            files_inspected += 1

                        label_val = analysis.classification.sensitivity_label.value
                        if label_val == SensitivityLevel.RESTRICTED.value:
                            restricted_count += 1
                            sensitive_files_count += 1
                        elif label_val == SensitivityLevel.CONFIDENTIAL.value:
                            confidential_count += 1
                            sensitive_files_count += 1
                        elif label_val == SensitivityLevel.INTERNAL.value:
                            internal_count += 1
                        elif label_val == SensitivityLevel.PUBLIC.value:
                            public_count += 1
                        else:
                            not_assessed_count += 1

                        classification_record = FileClassification(
                            id=str(uuid.uuid4()),
                            scanned_file_id=scanned_record.id,
                            sensitivity_label=label_val,
                            policy_version=analysis.classification.policy_version,
                            classified_at=datetime.now(timezone.utc),
                            inspection_status=analysis.inspection_status.value,
                            explanation=analysis.classification.explanation,
                            highest_confidence=analysis.classification.highest_confidence,
                        )
                        db.add(classification_record)

                        for finding in analysis.findings:
                            f_record = DetectionFinding(
                                id=str(uuid.uuid4()),
                                scanned_file_id=scanned_record.id,
                                rule_id=finding.rule_id,
                                rule_version="1.0.0",
                                category=finding.category.value,
                                confidence=finding.confidence.value,
                                occurrence_count=finding.occurrence_count,
                                detected_at=datetime.now(timezone.utc),
                            )
                            db.add(f_record)
                            if finding.category == DetectionCategory.PII:
                                pii_count += finding.occurrence_count
                            elif finding.category == DetectionCategory.CREDENTIALS:
                                credential_count += finding.occurrence_count
                            elif finding.category == DetectionCategory.FINANCIAL:
                                financial_count += finding.occurrence_count
                            elif finding.category == DetectionCategory.DOCUMENT_LABEL:
                                confidential_label_count += finding.occurrence_count
                    else:
                        if meta.status == "skipped":
                            skipped_count += 1
                        else:
                            error_count += 1
                        not_assessed_count += 1
                        classification_record = FileClassification(
                            id=str(uuid.uuid4()),
                            scanned_file_id=scanned_record.id,
                            sensitivity_label=SensitivityLevel.NOT_ASSESSED.value,
                            policy_version=POLICY_VERSION,
                            classified_at=datetime.now(timezone.utc),
                            inspection_status=meta.status,
                            explanation=f"File not inspected due to status: {meta.status} ({meta.error_message or 'n/a'}).",
                            highest_confidence="N/A",
                        )
                        db.add(classification_record)

                    # Periodic commit to prevent large transactions
                    if (processed_count + skipped_count + error_count) % 50 == 0:
                        db.commit()

            except ScanCancelledException:
                final_status = "cancelled"
                error_message = "Scan was cancelled by user request"
                logger.info(f"Scan job {scan_id} marked as cancelled", extra={"event": "scan_cancelled", "scan_id": scan_id})
            except Exception as err:
                final_status = "failed"
                error_message = f"Scanner error: {str(err)}"
                logger.error(f"Fatal error in scan job {scan_id}: {str(err)}", exc_info=True, extra={"event": "scan_fatal_error"})
            finally:
                # Update job final metrics
                job.status = final_status
                job.completed_at = datetime.now(timezone.utc)
                job.files_discovered = discovered_count
                job.files_processed = processed_count
                job.files_skipped = skipped_count
                job.error_count = error_count
                job.total_bytes_processed = total_bytes
                job.error_message = error_message

                # Phase 3: Persist ScanDetectionSummary
                detection_summary = ScanDetectionSummary(
                    id=str(uuid.uuid4()),
                    scan_job_id=scan_id,
                    files_inspected=files_inspected,
                    sensitive_files_count=sensitive_files_count,
                    public_count=public_count,
                    internal_count=internal_count,
                    confidential_count=confidential_count,
                    restricted_count=restricted_count,
                    not_assessed_count=not_assessed_count,
                    pii_count=pii_count,
                    credential_count=credential_count,
                    financial_count=financial_count,
                    confidential_label_count=confidential_label_count,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(detection_summary)
                db.commit()

                # Clean up active cancellation registration
                with self._lock:
                    self._cancellation_events.pop(scan_id, None)

                elapsed = round(time.time() - start_time, 2)
                logger.info(
                    f"Scan job {scan_id} finished [{final_status}] in {elapsed}s: "
                    f"{processed_count} processed, {skipped_count} skipped, {error_count} errors, {total_bytes} bytes",
                    extra={
                        "event": "scan_completed",
                        "scan_id": scan_id,
                        "status": final_status,
                        "processed": processed_count,
                        "duration_sec": elapsed,
                    },
                )


# Singleton scanner instance
scanner_engine = ScanEngine()
