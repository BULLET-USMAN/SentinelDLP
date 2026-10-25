"""Network Log and Telemetry Ingestion Service for SentinelDLP (Phase 7).

Orchestrates streaming parsing for:
- Zeek JSON logs (conn, dns, ssl, http)
- Suricata EVE JSON logs
- Offline PCAP files

Features:
- Duplicate record prevention via composite keys.
- Granular tracking of records processed, rejected, and errors.
- Sensor state initialization and health tracking.
"""

from datetime import datetime, timezone
import io
import json
import os
from typing import Generator, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.network import NetworkEvent, NetworkIngestionJob, NetworkSensor
from app.network.adapters.pcap_adapter import PcapAdapter
from app.network.adapters.suricata_adapter import SuricataAdapter
from app.network.adapters.zeek_adapter import ZeekAdapter
from app.network.schemas import NetworkIngestResponse, NormalizedNetworkEvent


class NetworkIngestionService:
    """Service layer managing ingestion pipelines, parsing, and job auditing."""

    @staticmethod
    def ensure_sensor(
        db: Session, sensor_id: str, technology: str, version: Optional[str] = "1.0.0"
    ) -> NetworkSensor:
        """Ensure a network sensor record exists, or register it if new."""
        sensor = db.query(NetworkSensor).filter(NetworkSensor.sensor_id == sensor_id).first()
        if not sensor:
            sensor = NetworkSensor(
                sensor_id=sensor_id,
                technology=technology.upper(),
                version=version,
                health_status="ACTIVE",
                enabled=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(sensor)
            db.commit()
            db.refresh(sensor)
        return sensor

    @classmethod
    def ingest_stream_or_file(
        cls,
        db: Session,
        sensor_id: str,
        source_format: str,
        file_path: Optional[str] = None,
        raw_content: Optional[str] = None,
    ) -> NetworkIngestResponse:
        """Parse and persist network telemetry from file or string content."""
        # 1. Determine Technology & Ensure Sensor
        fmt = source_format.upper()
        if fmt.startswith("ZEEK"):
            tech = "ZEEK"
        elif fmt.startswith("SURICATA"):
            tech = "SURICATA"
        elif fmt == "PCAP":
            tech = "PCAP_ANALYZER"
        else:
            tech = "SIMULATED"

        sensor = cls.ensure_sensor(db, sensor_id=sensor_id, technology=tech)

        # 2. Create Ingestion Job Record
        job = NetworkIngestionJob(
            sensor_id=sensor.sensor_id,
            source_format=fmt,
            file_path=file_path,
            start_time=datetime.now(timezone.utc),
            status="RUNNING",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        processed = 0
        rejected = 0
        duplicates = 0
        errors = 0
        events_to_add: List[NetworkEvent] = []
        seen_in_batch = set()

        try:
            # 3. Setup generator based on input and format
            if fmt == "PCAP":
                if not file_path or not os.path.exists(file_path):
                    raise FileNotFoundError(f"PCAP file not found: {file_path}")
                with open(file_path, "rb") as f:
                    generator = PcapAdapter.parse_pcap_stream(f, sensor_id=sensor.sensor_id)
                    for norm_event, is_valid, err_msg in generator:
                        if not is_valid or not norm_event:
                            rejected += 1
                            continue
                        event_key = (norm_event.sensor_id, norm_event.original_event_id)
                        if event_key in seen_in_batch or cls._is_duplicate(db, norm_event):
                            duplicates += 1
                            continue
                        seen_in_batch.add(event_key)
                        events_to_add.append(cls._to_db_model(norm_event))
                        processed += 1
            else:
                # Text/JSON lines generator
                def line_generator() -> Generator[str, None, None]:
                    if raw_content:
                        for l in raw_content.splitlines():
                            yield l
                    elif file_path and os.path.exists(file_path):
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            for l in f:
                                yield l
                    else:
                        return

                if tech == "ZEEK":
                    generator = ZeekAdapter.stream_parse_lines(line_generator(), format_type=fmt, sensor_id=sensor.sensor_id)
                else:  # SURICATA
                    generator = SuricataAdapter.stream_parse_lines(line_generator(), sensor_id=sensor.sensor_id)

                for norm_event, is_valid, err_msg in generator:
                    if not is_valid or not norm_event:
                        rejected += 1
                        if err_msg and "Malformed" in err_msg:
                            errors += 1
                        continue

                    event_key = (norm_event.sensor_id, norm_event.original_event_id)
                    if event_key in seen_in_batch or cls._is_duplicate(db, norm_event):
                        duplicates += 1
                        continue
                    seen_in_batch.add(event_key)

                    events_to_add.append(cls._to_db_model(norm_event))
                    processed += 1

                    # Batch flush every 500 records
                    if len(events_to_add) >= 500:
                        db.bulk_save_objects(events_to_add)
                        db.commit()
                        events_to_add.clear()

            # Final commit of remaining batch
            if events_to_add:
                db.bulk_save_objects(events_to_add)
                db.commit()

            # Update Job & Sensor
            job.completion_time = datetime.now(timezone.utc)
            job.records_processed = processed
            job.records_rejected = rejected
            job.duplicate_count = duplicates
            job.error_count = errors
            job.status = "COMPLETED"
            sensor.last_import_at = job.completion_time
            sensor.health_status = "ACTIVE"
            db.commit()

        except Exception as exc:
            db.rollback()
            job.completion_time = datetime.now(timezone.utc)
            job.records_processed = processed
            job.records_rejected = rejected
            job.duplicate_count = duplicates
            job.error_count = errors + 1
            job.status = "FAILED"
            job.error_summary = str(exc)
            sensor.health_status = "DEGRADED"
            sensor.coverage_gap_reason = f"Ingestion failure: {str(exc)}"
            db.commit()
            raise

        return NetworkIngestResponse(
            job_id=job.id,
            sensor_id=sensor.sensor_id,
            source_format=fmt,
            records_processed=processed,
            records_rejected=rejected,
            duplicate_count=duplicates,
            status=job.status,
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def _is_duplicate(db: Session, event: NormalizedNetworkEvent) -> bool:
        """Check if identical event has already been recorded."""
        if event.original_event_id:
            exists = (
                db.query(NetworkEvent.id)
                .filter(
                    NetworkEvent.sensor_id == event.sensor_id,
                    NetworkEvent.original_event_id == event.original_event_id,
                )
                .first()
            )
            if exists:
                return True

        # Fallback to 5-tuple + timestamp check
        exists_tuple = (
            db.query(NetworkEvent.id)
            .filter(
                NetworkEvent.sensor_id == event.sensor_id,
                NetworkEvent.timestamp == event.timestamp,
                NetworkEvent.source_ip == event.source_ip,
                NetworkEvent.destination_ip == event.destination_ip,
                NetworkEvent.destination_port == event.destination_port,
            )
            .first()
        )
        return bool(exists_tuple)

    @staticmethod
    def _to_db_model(event: NormalizedNetworkEvent) -> NetworkEvent:
        """Map NormalizedNetworkEvent schema to SQLAlchemy model."""
        return NetworkEvent(
            sensor_id=event.sensor_id,
            source_technology=event.source_technology,
            original_event_id=event.original_event_id,
            event_category=event.event_category,
            timestamp=event.timestamp,
            collected_at=datetime.now(timezone.utc),
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            transport_protocol=event.transport_protocol,
            application_protocol=event.application_protocol,
            direction=event.direction,
            connection_duration_seconds=event.connection_duration_seconds,
            bytes_source_to_dest=event.bytes_source_to_dest,
            bytes_dest_to_source=event.bytes_dest_to_source,
            total_bytes=event.total_bytes,
            packets_total=event.packets_total,
            dns_query=event.dns_query,
            dns_query_type=event.dns_query_type,
            dns_response_code=event.dns_response_code,
            tls_sni=event.tls_sni,
            tls_version=event.tls_version,
            http_method=event.http_method,
            http_host=event.http_host,
            http_uri_stem=event.http_uri_stem,
            alert_signature=event.alert_signature,
            alert_severity=event.alert_severity,
            evidence_provenance=event.evidence_provenance,
            capture_completeness=event.capture_completeness,
            is_simulated=event.is_simulated,
            processing_status="processed",
            metadata_json=event.metadata_json,
        )
