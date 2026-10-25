"""Data Exfiltration and Security Event Correlation Models for SentinelDLP (Phase 6).

Defines persistence schemas for:
- TransferEvent: Outbound transfer records (synthetic or imported) with provenance.
- ExfiltrationInvestigation: Central investigation incident entity with triage status.
- CorrelationRecord: Deterministic temporal correlation rule matches.
- InvestigationEvidenceLink: Provenance-tagged links tying file activity, archives, and transfers.

Ethical & Forensic Principles:
- Strict evidence provenance tracking: OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED.
- Explicit relationship categorization: temporal, circumstantial, verified.
- Causal modesty: events happening within windows are correlated, not assumed guilty without proof.
- Zero raw secrets or sensitive contents stored.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
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


class TransferEvent(Base):
    """Represents an outbound data transfer event (e.g. cloud upload, web POST, file transfer).
    
    Can originate from LAB_SIMULATED synthetic harnesses or future network collection taps.
    """

    __tablename__ = "transfer_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_endpoint_id = Column(String(64), nullable=False, index=True, default="endpoint-alpha-01")
    occurred_at = Column(DateTime(timezone=True), nullable=False, index=True)
    collected_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    direction = Column(String(16), nullable=False, default="OUTBOUND", index=True)  # OUTBOUND, INBOUND, LATERAL
    destination_category = Column(
        String(32), nullable=False, default="UNKNOWN", index=True
    )  # CLOUD_STORAGE, EXTERNAL_IP, FILE_SHARING, WEB_POST, UNKNOWN, CORPORATE_AUTHORIZED
    destination_host = Column(String(255), nullable=False, index=True)  # e.g., mega.nz, 198.51.100.42
    protocol = Column(String(16), nullable=False, default="HTTPS")  # HTTPS, SFTP, SMB, FTP
    byte_count = Column(Integer, nullable=False, index=True)  # Size in bytes
    
    verified_file_reference = Column(String(255), nullable=True)  # File hash or name if confirmed
    trusted_process_reference = Column(String(255), nullable=True)  # curl.exe, rclone.exe, browser
    evidence_source = Column(String(64), nullable=False, default="LAB_SYNTHETIC_HARNESS")
    evidence_provenance = Column(
        String(32), nullable=False, default="LAB_SIMULATED", index=True
    )  # OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED
    is_simulated = Column(Boolean, nullable=False, default=True)
    status = Column(String(32), nullable=False, default="recorded")
    context_data = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_transfer_events_occurred_bytes", "occurred_at", "byte_count"),
        Index("ix_transfer_events_dest_sim", "destination_host", "is_simulated"),
    )


class ExfiltrationInvestigation(Base):
    """Represents a correlated exfiltration investigation entity created by detection rules."""

    __tablename__ = "exfiltration_investigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(
        String(32), nullable=False, default="OPEN", index=True
    )  # OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, INCONCLUSIVE
    
    # Quantitative Risk Assessment (0-100)
    risk_score = Column(Integer, nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    evidence_confidence = Column(
        String(16), nullable=False, default="MEDIUM", index=True
    )  # LOW, MEDIUM, HIGH
    evidence_completeness = Column(
        String(16), nullable=False, default="PARTIAL", index=True
    )  # COMPLETE, PARTIAL, INSUFFICIENT

    primary_endpoint_id = Column(String(64), nullable=True, index=True)
    correlation_window_minutes = Column(Integer, nullable=False, default=15)
    rules_triggered_count = Column(Integer, nullable=False, default=1)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    assigned_analyst = Column(String(128), nullable=True)
    investigation_notes = Column(Text, nullable=True)

    # Relationships
    correlation_records = relationship(
        "CorrelationRecord",
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="CorrelationRecord.matched_at.desc()",
    )
    evidence_links = relationship(
        "InvestigationEvidenceLink",
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="InvestigationEvidenceLink.timestamp.asc()",
    )

    __table_args__ = (
        Index("ix_exfil_inv_status_risk", "status", "risk_score"),
        Index("ix_exfil_inv_created_sev", "created_at", "severity"),
    )


class CorrelationRecord(Base):
    """Specific correlation rule match linking evidence to an investigation."""

    __tablename__ = "correlation_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(
        String(36),
        ForeignKey("exfiltration_investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id = Column(String(32), nullable=False, index=True)  # e.g., EXFIL-001 ... EXFIL-008
    rule_name = Column(String(128), nullable=False)
    rule_version = Column(String(16), nullable=False, default="1.0.0")
    score_contribution = Column(Integer, nullable=False, default=0)
    relationship_type = Column(
        String(32), nullable=False, default="temporal"
    )  # temporal, circumstantial, verified
    evidence_completeness = Column(String(16), nullable=False, default="PARTIAL")
    matched_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    summary = Column(String(255), nullable=False)
    details_json = Column(Text, nullable=True)

    investigation = relationship("ExfiltrationInvestigation", back_populates="correlation_records")


class InvestigationEvidenceLink(Base):
    """Granular piece of evidence (file event, archive, transfer) linked to an investigation with explicit provenance."""

    __tablename__ = "investigation_evidence_links"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(
        String(36),
        ForeignKey("exfiltration_investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type = Column(
        String(32), nullable=False, index=True
    )  # file_activity, transfer_event, risk_assessment, archive_activity, file_classification
    evidence_id = Column(String(64), nullable=False, index=True)
    evidence_provenance = Column(
        String(32), nullable=False, default="OBSERVED"
    )  # OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED
    relationship_nature = Column(
        String(32), nullable=False, default="temporal"
    )  # temporal, circumstantial, verified
    timestamp = Column(DateTime(timezone=True), nullable=False)
    description = Column(String(255), nullable=False)
    metadata_json = Column(Text, nullable=True)

    investigation = relationship("ExfiltrationInvestigation", back_populates="evidence_links")

    __table_args__ = (
        Index("ix_evidence_links_inv_time", "investigation_id", "timestamp"),
    )
