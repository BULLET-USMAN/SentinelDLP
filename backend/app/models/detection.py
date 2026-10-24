"""Detection Database Models for SentinelDLP (Phase 3).

Defines persistence schemas for Detection Findings, File Classifications,
and Scan Detection Summaries.
Ensures zero sensitive file content or credentials are stored.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
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


class DetectionFinding(Base):
    """Represents a sanitized sensitive data detection finding for a file."""

    __tablename__ = "detection_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scanned_file_id = Column(
        String(36),
        ForeignKey("scanned_files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule_id = Column(String(64), nullable=False, index=True)
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    category = Column(String(64), nullable=False, index=True)
    confidence = Column(String(16), nullable=False, index=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scanned_file = relationship("ScannedFile", back_populates="detection_findings")

    __table_args__ = (
        Index("ix_detection_findings_file_category", "scanned_file_id", "category"),
    )

    def __repr__(self) -> str:
        return (
            f"<DetectionFinding(id='{self.id}', rule='{self.rule_id}', "
            f"category='{self.category}', confidence='{self.confidence}', "
            f"count={self.occurrence_count})>"
        )


class FileClassification(Base):
    """Represents the sensitivity classification outcome for a scanned file."""

    __tablename__ = "file_classifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scanned_file_id = Column(
        String(36),
        ForeignKey("scanned_files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    sensitivity_label = Column(String(32), nullable=False, index=True)
    policy_version = Column(String(64), nullable=False)
    classified_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    inspection_status = Column(String(32), nullable=False, index=True)
    explanation = Column(Text, nullable=False)
    highest_confidence = Column(String(16), nullable=False, default="NONE")

    # Relationships
    scanned_file = relationship("ScannedFile", back_populates="classification")

    def __repr__(self) -> str:
        return (
            f"<FileClassification(id='{self.id}', label='{self.sensitivity_label}', "
            f"confidence='{self.highest_confidence}')>"
        )


class ScanDetectionSummary(Base):
    """Aggregated detection and classification metrics for a scan job."""

    __tablename__ = "scan_detection_summaries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(
        String(36),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    files_inspected = Column(Integer, nullable=False, default=0)
    sensitive_files_count = Column(Integer, nullable=False, default=0)
    public_count = Column(Integer, nullable=False, default=0)
    internal_count = Column(Integer, nullable=False, default=0)
    confidential_count = Column(Integer, nullable=False, default=0)
    restricted_count = Column(Integer, nullable=False, default=0)
    not_assessed_count = Column(Integer, nullable=False, default=0)

    pii_count = Column(Integer, nullable=False, default=0)
    credential_count = Column(Integer, nullable=False, default=0)
    financial_count = Column(Integer, nullable=False, default=0)
    confidential_label_count = Column(Integer, nullable=False, default=0)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan_job = relationship("ScanJob", back_populates="detection_summary")

    def __repr__(self) -> str:
        return (
            f"<ScanDetectionSummary(scan_job_id='{self.scan_job_id}', "
            f"inspected={self.files_inspected}, sensitive={self.sensitive_files_count})>"
        )
