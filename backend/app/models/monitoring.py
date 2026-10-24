"""Monitoring Database Models for SentinelDLP (Phase 4).

Defines persistence schemas for Monitoring Configurations, File Activity Events,
and Monitoring Health Sessions.
Strictly adheres to defensive monitoring principles: zero raw secrets or passwords stored.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.db.base import Base


class MonitoringConfiguration(Base):
    """Administrator-configured monitoring parameters for an authorized directory."""

    __tablename__ = "monitoring_configurations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    root_id = Column(String(64), nullable=False, unique=True, index=True)
    root_path = Column(String(512), nullable=False)
    enabled = Column(Boolean, nullable=False, default=False)
    recursive = Column(Boolean, nullable=False, default=True)
    excluded_patterns = Column(Text, nullable=True)  # JSON-encoded array of excluded names/extensions

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    events = relationship(
        "FileActivityEvent",
        back_populates="configuration",
        cascade="all, delete-orphan",
        order_by="desc(FileActivityEvent.occurred_at)",
    )

    def __repr__(self) -> str:
        return f"<MonitoringConfiguration(root_id='{self.root_id}', enabled={self.enabled})>"


class FileActivityEvent(Base):
    """Represents an individual normalized filesystem activity event."""

    __tablename__ = "file_activity_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    monitoring_config_id = Column(
        String(36),
        ForeignKey("monitoring_configurations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    root_id = Column(String(64), nullable=False, index=True)

    # Event details
    event_type = Column(String(32), nullable=False, index=True)
    is_directory = Column(Boolean, nullable=False, default=False)
    relative_path = Column(String(1024), nullable=False, index=True)
    previous_relative_path = Column(String(1024), nullable=True)

    # Timestamps
    occurred_at = Column(DateTime(timezone=True), nullable=False, index=True)
    collected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # Processing and Classification linkage
    status = Column(String(32), nullable=False, default="pending", index=True)
    associated_file_id = Column(
        String(36),
        ForeignKey("scanned_files.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sensitivity_label = Column(String(32), nullable=True, index=True)
    file_type = Column(String(64), nullable=True)
    size_bytes = Column(BigInteger, nullable=True)
    sha256_hash = Column(String(64), nullable=True)

    # Telemetry and Diagnostics
    event_source = Column(String(32), nullable=False, default="watchdog")
    error_category = Column(String(64), nullable=True)

    # Relationships
    configuration = relationship("MonitoringConfiguration", back_populates="events")
    associated_file = relationship("ScannedFile")

    __table_args__ = (
        Index("ix_activity_events_root_occurred", "root_id", "occurred_at"),
        Index("ix_activity_events_type_status", "event_type", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<FileActivityEvent(id='{self.id}', type='{self.event_type}', "
            f"path='{self.relative_path}', status='{self.status}')>"
        )


class MonitoringSession(Base):
    """Tracks the operational lifecycle, telemetry, and health of an active observer."""

    __tablename__ = "monitoring_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    root_id = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="starting", index=True)

    started_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    stopped_at = Column(DateTime(timezone=True), nullable=True)

    # Operational metrics
    raw_event_count = Column(Integer, nullable=False, default=0)
    processed_event_count = Column(Integer, nullable=False, default=0)
    deduplicated_count = Column(Integer, nullable=False, default=0)
    queue_overflow_count = Column(Integer, nullable=False, default=0)

    last_event_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<MonitoringSession(id='{self.id}', root_id='{self.root_id}', "
            f"status='{self.status}', processed={self.processed_event_count})>"
        )
