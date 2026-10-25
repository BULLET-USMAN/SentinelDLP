"""Read-only filesystem monitoring event tools."""

from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.monitoring import FileActivityEvent
from app.ai.security.sanitization import sanitize_evidence_dict


def get_file_activity(db: Session, event_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve normalized file activity event details."""
    if not event_id:
        return None

    event = db.query(FileActivityEvent).filter(FileActivityEvent.id == event_id.strip()).first()
    if not event:
        return None

    data = {
        "event_id": event.id,
        "event_type": event.event_type,
        "relative_path": event.relative_path,
        "root_id": event.root_id,
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "file_size": event.file_size,
        "event_source": event.event_source,
        "processing_status": event.processing_status,
        "associated_file_id": event.associated_file_id,
    }
    return sanitize_evidence_dict(data)
