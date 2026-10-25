"""Transfer Telemetry Service for SentinelDLP (Phase 6).

Handles ingestion, validation, and querying of outbound transfer events.
Provides lab simulation fixtures for demonstration and verification.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from app.exfiltration.policies import is_archive_file
from app.exfiltration.provenance import EvidenceProvenance
from app.exfiltration.schemas import TransferEventCreate
from app.models.exfiltration import TransferEvent


class TransferService:
    """Service layer for recording and managing outbound data transfer evidence."""

    @staticmethod
    def record_transfer(db: Session, payload: TransferEventCreate) -> TransferEvent:
        """Persist a single transfer event record."""
        event = TransferEvent(
            source_endpoint_id=payload.source_endpoint_id,
            occurred_at=payload.occurred_at,
            direction=payload.direction,
            destination_category=payload.destination_category,
            destination_host=payload.destination_host,
            protocol=payload.protocol,
            byte_count=payload.byte_count,
            verified_file_reference=payload.verified_file_reference,
            trusted_process_reference=payload.trusted_process_reference,
            evidence_source=payload.evidence_source,
            evidence_provenance=payload.evidence_provenance.value,
            is_simulated=payload.is_simulated,
            context_data=payload.context_data,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def batch_import_transfers(db: Session, events: List[TransferEventCreate]) -> List[TransferEvent]:
        """Bulk import transfer events."""
        db_records = []
        for payload in events:
            event = TransferEvent(
                source_endpoint_id=payload.source_endpoint_id,
                occurred_at=payload.occurred_at,
                direction=payload.direction,
                destination_category=payload.destination_category,
                destination_host=payload.destination_host,
                protocol=payload.protocol,
                byte_count=payload.byte_count,
                verified_file_reference=payload.verified_file_reference,
                trusted_process_reference=payload.trusted_process_reference,
                evidence_source=payload.evidence_source,
                evidence_provenance=payload.evidence_provenance.value,
                is_simulated=payload.is_simulated,
                context_data=payload.context_data,
            )
            db.add(event)
            db_records.append(event)
        db.commit()
        for rec in db_records:
            db.refresh(rec)
        return db_records

    @staticmethod
    def list_transfers(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        destination_host: Optional[str] = None,
        is_simulated: Optional[bool] = None,
    ) -> Tuple[List[TransferEvent], int]:
        """Query transfers with pagination and filtering."""
        query = db.query(TransferEvent)
        if destination_host:
            query = query.filter(TransferEvent.destination_host.ilike(f"%{destination_host}%"))
        if is_simulated is not None:
            query = query.filter(TransferEvent.is_simulated == is_simulated)

        total = query.count()
        transfers = (
            query.order_by(TransferEvent.occurred_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return transfers, total

    @staticmethod
    def generate_lab_synthetic_scenarios(db: Session, scenario_type: str = "cloud_exfiltration") -> List[TransferEvent]:
        """Generate a realistic lab simulation fixture for exfiltration testing.

        Scenarios:
        - 'cloud_exfiltration': High-volume transfer to untrusted cloud storage (e.g. mega.nz).
        - 'chunked_exfiltration': Multiple repeated transfers to an external IP.
        - 'benign_sync': Approved backup transfer to backup.internal.corp.
        """
        now = datetime.now(timezone.utc)
        events_to_create: List[TransferEventCreate] = []

        if scenario_type == "cloud_exfiltration":
            events_to_create.append(
                TransferEventCreate(
                    source_endpoint_id="endpoint-alpha-01",
                    occurred_at=now - timedelta(minutes=2),
                    direction="OUTBOUND",
                    destination_category="CLOUD_STORAGE",
                    destination_host="mega.nz/upload/v2",
                    protocol="HTTPS",
                    byte_count=18_500_000,  # 18.5 MB
                    verified_file_reference="classified_records_archive.zip",
                    trusted_process_reference="curl.exe",
                    evidence_source="LAB_SYNTHETIC_HARNESS",
                    evidence_provenance=EvidenceProvenance.LAB_SIMULATED,
                    is_simulated=True,
                    context_data='{"simulated_scenario": "cloud_exfiltration", "lab_tag": "EXFIL-TEST-001"}',
                )
            )
        elif scenario_type == "chunked_exfiltration":
            for i in range(4):
                events_to_create.append(
                    TransferEventCreate(
                        source_endpoint_id="endpoint-alpha-01",
                        occurred_at=now - timedelta(minutes=6 - i),
                        direction="OUTBOUND",
                        destination_category="EXTERNAL_IP",
                        destination_host=f"198.51.100.4{i}:8443",
                        protocol="HTTPS",
                        byte_count=3_200_000,
                        trusted_process_reference="python.exe",
                        evidence_source="LAB_SYNTHETIC_HARNESS",
                        evidence_provenance=EvidenceProvenance.LAB_SIMULATED,
                        is_simulated=True,
                        context_data=f'{{"simulated_scenario": "chunked_exfiltration", "chunk_index": {i}}}',
                    )
                )
        else:  # benign_sync
            events_to_create.append(
                TransferEventCreate(
                    source_endpoint_id="endpoint-alpha-01",
                    occurred_at=now - timedelta(minutes=5),
                    direction="OUTBOUND",
                    destination_category="CORPORATE_AUTHORIZED",
                    destination_host="backup.internal.corp",
                    protocol="HTTPS",
                    byte_count=50_000_000,
                    trusted_process_reference="backup-agent.exe",
                    evidence_source="LAB_SYNTHETIC_HARNESS",
                    evidence_provenance=EvidenceProvenance.LAB_SIMULATED,
                    is_simulated=True,
                    context_data='{"simulated_scenario": "benign_sync"}',
                )
            )

        return TransferService.batch_import_transfers(db, events_to_create)
