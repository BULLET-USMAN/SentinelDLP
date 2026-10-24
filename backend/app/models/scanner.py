"""Scanner Database Models for SentinelDLP (Phase 2).

Defines persistence schemas for Scan Jobs and File Inventory Results.
Ensures zero sensitive file content or credentials are stored.
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


class ScanJob(Base):
    """Represents an authorized scan job run."""

    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    root_id = Column(String(64), nullable=False, index=True)
    root_path = Column(String(512), nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    started_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Aggregated metrics
    files_discovered = Column(Integer, default=0, nullable=False)
    files_processed = Column(Integer, default=0, nullable=False)
    files_skipped = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    total_bytes_processed = Column(BigInteger, default=0, nullable=False)
    error_message = Column(Text, nullable=True)

    # Relationships
    files = relationship(
        "ScannedFile",
        back_populates="scan_job",
        cascade="all, delete-orphan",
        order_by="ScannedFile.relative_path",
    )

    def __repr__(self) -> str:
        return f"<ScanJob(id='{self.id}', root_id='{self.root_id}', status='{self.status}')>"


class ScannedFile(Base):
    """Represents an individual discovered file inventory record."""

    __tablename__ = "scanned_files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(
        String(36),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    filename = Column(String(255), nullable=False, index=True)
    relative_path = Column(String(1024), nullable=False, index=True)
    file_extension = Column(String(32), nullable=False, index=True)
    detected_type = Column(String(64), nullable=False, index=True)
    size_bytes = Column(BigInteger, nullable=False, default=0)

    # Filesystem timestamps
    created_at = Column(DateTime(timezone=True), nullable=True)
    modified_at = Column(DateTime(timezone=True), nullable=True)

    # Cryptographic integrity
    sha256_hash = Column(String(64), nullable=True, index=True)
    scan_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Processing status & security flags
    status = Column(String(32), nullable=False, default="scanned", index=True)
    error_message = Column(String(512), nullable=True)
    type_mismatch = Column(Boolean, nullable=False, default=False, index=True)

    # Relationships
    scan_job = relationship("ScanJob", back_populates="files")

    __table_args__ = (
        Index("ix_scanned_files_job_status", "scan_job_id", "status"),
        Index("ix_scanned_files_job_type", "scan_job_id", "detected_type"),
    )

    def __repr__(self) -> str:
        return f"<ScannedFile(id='{self.id}', path='{self.relative_path}', status='{self.status}')>"
