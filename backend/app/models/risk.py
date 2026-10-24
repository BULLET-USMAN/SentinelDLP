"""Risk Assessment and Security Alert Models for SentinelDLP (Phase 5).

Defines persistence schemas for:
- RiskAssessment: Deterministic numerical score, severity, and explainable findings.
- RuleMatch: Granular rule contributions and sanitized evidence.
- SecurityAlert: Actionable SOC alerts with deduplication, suppression, and lifecycle status.
- AlertAuditLog: Full immutable audit trail for analyst triage and status transitions.

Strictly preserves zero-leakage security: no credentials or raw sensitive payloads stored.
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


class RiskAssessment(Base):
    """Represents a deterministic threat risk assessment evaluated for a security event."""

    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(
        String(36),
        ForeignKey("file_activity_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    root_id = Column(String(64), nullable=False, index=True)
    associated_file_id = Column(
        String(36),
        ForeignKey("scanned_files.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Core scoring fields
    risk_score = Column(Integer, nullable=False, index=True)  # Normalized 0–100
    severity = Column(String(16), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    evidence_completeness = Column(
        String(16), nullable=False, default="COMPLETE"
    )  # COMPLETE, PARTIAL, INSUFFICIENT
    detection_confidence = Column(
        String(16), nullable=False, default="HIGH"
    )  # LOW, MEDIUM, HIGH
    scoring_policy_version = Column(String(32), nullable=False, default="1.0.0")
    assessment_status = Column(
        String(32), nullable=False, default="assessed", index=True
    )  # assessed, warning, incomplete, suppressed

    # Explainability & Guidance
    explanation = Column(Text, nullable=False)
    limitations = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)

    assessed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    event = relationship("FileActivityEvent")
    associated_file = relationship("ScannedFile")
    rule_matches = relationship(
        "RuleMatch",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="desc(RuleMatch.score_contribution)",
    )
    alert = relationship(
        "SecurityAlert",
        back_populates="assessment",
        uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_risk_assessments_root_severity", "root_id", "severity"),
        Index("ix_risk_assessments_root_score", "root_id", "risk_score"),
    )

    def __repr__(self) -> str:
        return (
            f"<RiskAssessment(id='{self.id}', score={self.risk_score}, "
            f"severity='{self.severity}', event='{self.event_id}')>"
        )


class RuleMatch(Base):
    """Represents a specific detection rule triggered during a risk assessment."""

    __tablename__ = "rule_matches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id = Column(
        String(36),
        ForeignKey("risk_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id = Column(String(64), nullable=False, index=True)
    rule_name = Column(String(128), nullable=False)
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    score_contribution = Column(Integer, nullable=False, default=0)
    severity_impact = Column(String(16), nullable=False, default="LOW")

    match_timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    evidence_data = Column(Text, nullable=True)  # JSON-sanitized key/value context

    # Relationships
    assessment = relationship("RiskAssessment", back_populates="rule_matches")

    def __repr__(self) -> str:
        return (
            f"<RuleMatch(rule='{self.rule_id}', points={self.score_contribution}, "
            f"severity='{self.severity_impact}')>"
        )


class SecurityAlert(Base):
    """Represents an actionable security alert created from an elevated risk assessment."""

    __tablename__ = "security_alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id = Column(
        String(36),
        ForeignKey("risk_assessments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    root_id = Column(String(64), nullable=False, index=True)

    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Integer, nullable=False, index=True)

    # Lifecycle Status: OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    status = Column(String(32), nullable=False, default="OPEN", index=True)

    # Deduplication and suppression
    deduplication_key = Column(String(128), nullable=False, index=True)
    repeat_count = Column(Integer, nullable=False, default=1)
    suppression_window_seconds = Column(Integer, nullable=False, default=300)

    recommended_action = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Relationships
    assessment = relationship("RiskAssessment", back_populates="alert")
    audit_logs = relationship(
        "AlertAuditLog",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="desc(AlertAuditLog.performed_at)",
    )

    __table_args__ = (
        Index("ix_security_alerts_root_status", "root_id", "status"),
        Index("ix_security_alerts_severity_status", "severity", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityAlert(id='{self.id}', title='{self.title[:30]}', "
            f"severity='{self.severity}', score={self.risk_score}, status='{self.status}')>"
        )


class AlertAuditLog(Base):
    """Immutable audit trail for tracking analyst triage actions and status transitions."""

    __tablename__ = "alert_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(
        String(36),
        ForeignKey("security_alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_status = Column(String(32), nullable=False)
    new_status = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False)  # acknowledge, investigate, resolve, false_positive, reopen
    analyst_notes = Column(Text, nullable=True)
    performed_by = Column(String(64), nullable=False, default="security_analyst")
    performed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    alert = relationship("SecurityAlert", back_populates="audit_logs")

    def __repr__(self) -> str:
        return (
            f"<AlertAuditLog(alert_id='{self.alert_id}', {self.previous_status} -> {self.new_status}, "
            f"action='{self.action}')>"
        )
