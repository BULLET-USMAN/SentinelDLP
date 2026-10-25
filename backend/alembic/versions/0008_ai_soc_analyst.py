"""AI-powered SOC Analyst, investigation reports, and conversation schemas for SentinelDLP Phase 9.

Revision ID: 0008_ai_soc_analyst
Revises: 0007_network_monitoring
Create Date: 2026-10-25 17:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008_ai_soc_analyst"
down_revision: Union[str, None] = "0007_network_monitoring"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create ai_investigation_reports table
    op.create_table(
        "ai_investigation_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("alert_id", sa.String(length=36), nullable=True),
        sa.Column("model_id", sa.String(length=64), nullable=False),
        sa.Column("provider_type", sa.String(length=32), nullable=False, server_default="mock"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="COMPLETED"),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("assessment", sa.Text(), nullable=False),
        sa.Column("confidence_assessment", sa.String(length=32), nullable=False, server_default="PARTIAL_SUPPORT"),
        sa.Column("evidence_completeness", sa.String(length=32), nullable=False, server_default="PARTIAL"),
        sa.Column("observed_facts_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("possible_explanations_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("missing_evidence_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("recommended_actions_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("mitre_attack_mappings_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("evidence_references_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tool_calls_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("prompt_template_version", sa.String(length=16), nullable=False, server_default="v1.0"),
        sa.Column("report_schema_version", sa.String(length=16), nullable=False, server_default="v1.0"),
        sa.Column("analyst_review_status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("analyst_feedback_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("execution_duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["investigation_id"], ["exfiltration_investigations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_investigation_reports_investigation_id", "ai_investigation_reports", ["investigation_id"])
    op.create_index("ix_ai_investigation_reports_alert_id", "ai_investigation_reports", ["alert_id"])
    op.create_index("ix_ai_investigation_reports_created_at", "ai_investigation_reports", ["created_at"])
    op.create_index("ix_ai_investigation_reports_review_status", "ai_investigation_reports", ["analyst_review_status"])

    # 2. Create ai_conversation_sessions table
    op.create_table(
        "ai_conversation_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("alert_id", sa.String(length=36), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=False, server_default="soc_analyst"),
        sa.Column("title", sa.String(length=255), nullable=False, server_default="Security Investigation Inquiry"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("model_id", sa.String(length=64), nullable=False, server_default="mock-sentinel-v1"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["exfiltration_investigations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_conversation_sessions_investigation_id", "ai_conversation_sessions", ["investigation_id"])
    op.create_index("ix_ai_conversation_sessions_alert_id", "ai_conversation_sessions", ["alert_id"])
    op.create_index("ix_ai_conversation_sessions_updated_at", "ai_conversation_sessions", ["updated_at"])

    # 3. Create ai_conversation_messages table
    op.create_table(
        "ai_conversation_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("sanitized", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("evidence_references_json", sa.Text(), nullable=True, server_default="[]"),
        sa.Column("tool_invocations_json", sa.Text(), nullable=True, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["ai_conversation_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_conversation_messages_session_id", "ai_conversation_messages", ["session_id"])
    op.create_index("ix_ai_conversation_messages_created_at", "ai_conversation_messages", ["created_at"])

    # 4. Create ai_tool_audit_events table
    op.create_table(
        "ai_tool_audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("report_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("arguments_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="SUCCESS"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("execution_duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("invoked_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_tool_audit_events_tool_name", "ai_tool_audit_events", ["tool_name"])
    op.create_index("ix_ai_tool_audit_events_session_id", "ai_tool_audit_events", ["session_id"])
    op.create_index("ix_ai_tool_audit_events_report_id", "ai_tool_audit_events", ["report_id"])
    op.create_index("ix_ai_tool_audit_events_invoked_at", "ai_tool_audit_events", ["invoked_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_tool_audit_events_invoked_at", table_name="ai_tool_audit_events")
    op.drop_index("ix_ai_tool_audit_events_report_id", table_name="ai_tool_audit_events")
    op.drop_index("ix_ai_tool_audit_events_session_id", table_name="ai_tool_audit_events")
    op.drop_index("ix_ai_tool_audit_events_tool_name", table_name="ai_tool_audit_events")
    op.drop_table("ai_tool_audit_events")

    op.drop_index("ix_ai_conversation_messages_created_at", table_name="ai_conversation_messages")
    op.drop_index("ix_ai_conversation_messages_session_id", table_name="ai_conversation_messages")
    op.drop_table("ai_conversation_messages")

    op.drop_index("ix_ai_conversation_sessions_updated_at", table_name="ai_conversation_sessions")
    op.drop_index("ix_ai_conversation_sessions_alert_id", table_name="ai_conversation_sessions")
    op.drop_index("ix_ai_conversation_sessions_investigation_id", table_name="ai_conversation_sessions")
    op.drop_table("ai_conversation_sessions")

    op.drop_index("ix_ai_investigation_reports_review_status", table_name="ai_investigation_reports")
    op.drop_index("ix_ai_investigation_reports_created_at", table_name="ai_investigation_reports")
    op.drop_index("ix_ai_investigation_reports_alert_id", table_name="ai_investigation_reports")
    op.drop_index("ix_ai_investigation_reports_investigation_id", table_name="ai_investigation_reports")
    op.drop_table("ai_investigation_reports")
