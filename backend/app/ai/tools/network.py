"""Read-only network telemetry and sensor inspection tools."""

from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from app.models.network import NetworkEvent, NetworkSensor
from app.ai.security.sanitization import sanitize_evidence_dict


def get_network_events(db: Session, limit: int = 15) -> List[Dict[str, Any]]:
    """Retrieve recent network telemetry events (Zeek/Suricata/PCAP)."""
    bound_limit = max(1, min(limit, 30))
    events = (
        db.query(NetworkEvent)
        .order_by(NetworkEvent.timestamp.desc())
        .limit(bound_limit)
        .all()
    )

    data = [
        {
            "event_id": ev.id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "source_technology": ev.source_technology,
            "source_ip": ev.source_ip,
            "destination_ip": ev.destination_ip,
            "destination_port": ev.destination_port,
            "protocol": ev.application_protocol or ev.transport_protocol,
            "bytes_total": ev.bytes_total,
            "direction": ev.direction,
            "dns_query": ev.dns_query,
            "tls_sni": ev.tls_sni,
            "ids_signature": ev.ids_signature,
        }
        for ev in events
    ]
    return [sanitize_evidence_dict(item) for item in data]


def get_sensor_status(db: Session, sensor_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve operational status and health metrics for a registered network sensor."""
    if not sensor_id:
        return None

    sensor = db.query(NetworkSensor).filter(NetworkSensor.sensor_id == sensor_id.strip()).first()
    if not sensor:
        return None

    data = {
        "sensor_id": sensor.sensor_id,
        "technology": sensor.technology,
        "health_status": sensor.health_status,
        "enabled": sensor.enabled,
        "coverage_gap_reason": sensor.coverage_gap_reason,
        "last_import_at": sensor.last_import_at.isoformat() if sensor.last_import_at else None,
    }
    return sanitize_evidence_dict(data)
