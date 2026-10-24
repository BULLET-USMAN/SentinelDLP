"""Risk scoring and security alert schema for SentinelDLP Phase 5.

Revision ID: 0005_risk_scoring_and_alerts
Revises: 0004_file_activity_monitoring
Create Date: 2026-10-24 17:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_risk_scoring_and_alerts"
down_revision: Union[str, None] = "0004_file_activity_monitoring"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create risk_assessments table
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("associated_file_id", sa.String(length=36), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("evidence_completeness", sa.String(length=16), nullable=False, server_default="COMPLETE"),
        sa.Column("detection_confidence", sa.String(length=16), nullable=False, server_default="HIGH"),
        sa.Column("scoring_policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("assessment_status", sa.String(length=32), nullable=False, server_default="assessed"),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["associated_file_id"],
            ["scanned_files.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["file_activity_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )
    op.create_index("ix_risk_assessments_event_id", "risk_assessments", ["event_id"], unique=True)
    op.create_index("ix_risk_assessments_root_id", "risk_assessments", ["root_id"], unique=False)
    op.create_index("ix_risk_assessments_associated_file_id", "risk_assessments", ["associated_file_id"], unique=False)
    op.create_index("ix_risk_assessments_risk_score", "risk_assessments", ["risk_score"], unique=False)
    op.create_index("ix_risk_assessments_severity", "risk_assessments", ["severity"], unique=False)
    op.create_index("ix_risk_assessments_assessment_status", "risk_assessments", ["assessment_status"], unique=False)
    op.create_index("ix_risk_assessments_assessed_at", "risk_assessments", ["assessed_at"], unique=False)
    op.create_index("ix_risk_assessments_root_severity", "risk_assessments", ["root_id", "severity"], unique=False)
    op.create_index("ix_risk_assessments_root_score", "risk_assessments", ["root_id", "risk_score"], unique=False)

    # 2. Create rule_matches table
    op.create_table(
        "rule_matches",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("score_contribution", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity_impact", sa.String(length=16), nullable=False, server_default="LOW"),
        sa.Column("match_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_data", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_matches_assessment_id", "rule_matches", ["assessment_id"], unique=False)
    op.create_index("ix_rule_matches_rule_id", "rule_matches", ["rule_id"], unique=False)

    # 3. Create security_alerts table
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("deduplication_key", sa.String(length=128), nullable=False),
        sa.Column("repeat_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("suppression_window_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assessment_id"),
    )
    op.create_index("ix_security_alerts_assessment_id", "security_alerts", ["assessment_id"], unique=True)
    op.create_index("ix_security_alerts_root_id", "security_alerts", ["root_id"], unique=False)
    op.create_index("ix_security_alerts_severity", "security_alerts", ["severity"], unique=False)
    op.create_index("ix_security_alerts_risk_score", "security_alerts", ["risk_score"], unique=False)
    op.create_index("ix_security_alerts_status", "security_alerts", ["status"], unique=False)
    op.create_index("ix_security_alerts_deduplication_key", "security_alerts", ["deduplication_key"], unique=False)
    op.create_index("ix_security_alerts_created_at", "security_alerts", ["created_at"], unique=False)
    op.create_index("ix_security_alerts_root_status", "security_alerts", ["root_id", "status"], unique=False)
    op.create_index("ix_security_alerts_severity_status", "security_alerts", ["severity", "status"], unique=False)

    # 4. Create alert_audit_logs table
    op.create_table(
        "alert_audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=False),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("performed_by", sa.String(length=64), nullable=False, server_default="security_analyst"),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["security_alerts.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_audit_logs_alert_id", "alert_audit_logs", ["alert_id"], unique=False)
    op.create_index("ix_alert_audit_logs_performed_at", "alert_audit_logs", ["performed_at"], unique=False)


def downgrade() -> None:
    op.drop_table("alert_audit_logs")
    op.drop_table("security_alerts")
    op.drop_table("rule_matches")
    op.drop_table("risk_assessments")
