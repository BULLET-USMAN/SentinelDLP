"""System Model Definitions for SentinelDLP (Phase 1 Baseline).

Only models genuinely required for Phase 1 infrastructure, system tracking,
and database migration verification are defined here.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.db.base import Base


class SystemAuditRecord(Base):
    """Tracks infrastructure and baseline platform lifecycle events."""

    __tablename__ = "system_audit_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_type = Column(String(64), nullable=False, index=True)
    component = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)
    message = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SystemAuditRecord(id={self.id}, event_type='{self.event_type}', status='{self.status}')>"
