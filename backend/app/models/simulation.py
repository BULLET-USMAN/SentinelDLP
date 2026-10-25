"""SQLAlchemy Models for Phase 10: Cyberattack Simulation & Detection Validation Laboratory.

Defines schemas for:
- SimulationRun: Execution record for a security test scenario.
- SimulationResult: Granular comparison between expected and observed security events.
- SimulationReport: Human-readable markdown audit and validation report.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from app.db.base import Base


class SimulationRun(Base):
    """Execution lifecycle and metadata for a security validation scenario."""

    __tablename__ = "simulation_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_id = Column(String(64), nullable=False, index=True)
    scenario_name = Column(String(128), nullable=False)
    status = Column(
        String(32),
        nullable=False,
        default="PENDING",
        index=True,
    )  # 'PENDING', 'RUNNING', 'PASSED', 'FAILED', 'PARTIAL', 'ERROR', 'CANCELLED'

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True, default=0)
    summary = Column(Text, nullable=True)

    # Serialized JSON execution logs and metrics
    metrics_json = Column(Text, nullable=False, default="{}")
    execution_log_json = Column(Text, nullable=False, default="[]")

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    results = relationship(
        "SimulationResult",
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    report = relationship(
        "SimulationReport",
        back_populates="run",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class SimulationResult(Base):
    """Detailed validation results comparing expected vs observed security artifacts."""

    __tablename__ = "simulation_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(
        String(36),
        ForeignKey("simulation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pass_status = Column(
        String(32),
        nullable=False,
        default="FAILED",
    )  # 'PASSED', 'FAILED', 'PARTIAL'

    expected_events_count = Column(Integer, nullable=False, default=0)
    actual_events_count = Column(Integer, nullable=False, default=0)

    expected_rules_json = Column(Text, nullable=False, default="[]")
    actual_rules_json = Column(Text, nullable=False, default="[]")
    matched_rules_json = Column(Text, nullable=False, default="[]")
    unmatched_rules_json = Column(Text, nullable=False, default="[]")
    unexpected_rules_json = Column(Text, nullable=False, default="[]")

    expected_alerts_count = Column(Integer, nullable=False, default=0)
    actual_alerts_count = Column(Integer, nullable=False, default=0)

    expected_investigations_count = Column(Integer, nullable=False, default=0)
    actual_investigations_count = Column(Integer, nullable=False, default=0)

    # Statistical Evaluation Metrics
    precision = Column(Float, nullable=False, default=0.0)
    recall = Column(Float, nullable=False, default=0.0)
    f1_score = Column(Float, nullable=False, default=0.0)
    false_positive_rate = Column(Float, nullable=False, default=0.0)
    latency_ms = Column(Float, nullable=False, default=0.0)

    failure_reasons_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    run = relationship("SimulationRun", back_populates="results")


class SimulationReport(Base):
    """Comprehensive markdown report generated upon scenario completion."""

    __tablename__ = "simulation_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(
        String(36),
        ForeignKey("simulation_runs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    title = Column(String(256), nullable=False)
    markdown_content = Column(Text, nullable=False)
    execution_metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    run = relationship("SimulationRun", back_populates="report")
