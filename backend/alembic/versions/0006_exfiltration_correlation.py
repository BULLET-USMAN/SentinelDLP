"""Exfiltration correlation and investigation schema for SentinelDLP Phase 6.

Revision ID: 0006_exfiltration_correlation
Revises: 0005_risk_scoring_and_alerts
Create Date: 2026-10-25 15:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0006_exfiltration_correlation"
down_revision: Union[str, None] = "0005_risk_scoring_and_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create transfer_events table
    op.create_table(
        "transfer_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_endpoint_id", sa.String(length=64), nullable=False, server_default="endpoint-alpha-01"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False, server_default="OUTBOUND"),
        sa.Column("destination_category", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("destination_host", sa.String(length=255), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False, server_default="HTTPS"),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("verified_file_reference", sa.String(length=255), nullable=True),
        sa.Column("trusted_process_reference", sa.String(length=255), nullable=True),
        sa.Column("evidence_source", sa.String(length=64), nullable=False, server_default="LAB_SYNTHETIC_HARNESS"),
        sa.Column("evidence_provenance", sa.String(length=32), nullable=False, server_default="LAB_SIMULATED"),
        sa.Column("is_simulated", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="recorded"),
        sa.Column("context_data", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_transfer_events_source_endpoint_id", "transfer_events", ["source_endpoint_id"])
    op.create_index("ix_transfer_events_occurred_at", "transfer_events", ["occurred_at"])
    op.create_index("ix_transfer_events_direction", "transfer_events", ["direction"])
    op.create_index("ix_transfer_events_destination_category", "transfer_events", ["destination_category"])
    op.create_index("ix_transfer_events_destination_host", "transfer_events", ["destination_host"])
    op.create_index("ix_transfer_events_byte_count", "transfer_events", ["byte_count"])
    op.create_index("ix_transfer_events_evidence_provenance", "transfer_events", ["evidence_provenance"])
    op.create_index("ix_transfer_events_occurred_bytes", "transfer_events", ["occurred_at", "byte_count"])
    op.create_index("ix_transfer_events_dest_sim", "transfer_events", ["destination_host", "is_simulated"])

    # 2. Create exfiltration_investigations table
    op.create_table(
        "exfiltration_investigations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("evidence_confidence", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("evidence_completeness", sa.String(length=16), nullable=False, server_default="PARTIAL"),
        sa.Column("primary_endpoint_id", sa.String(length=64), nullable=True),
        sa.Column("correlation_window_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("rules_triggered_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_analyst", sa.String(length=128), nullable=True),
        sa.Column("investigation_notes", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exfiltration_investigations_status", "exfiltration_investigations", ["status"])
    op.create_index("ix_exfiltration_investigations_risk_score", "exfiltration_investigations", ["risk_score"])
    op.create_index("ix_exfiltration_investigations_severity", "exfiltration_investigations", ["severity"])
    op.create_index("ix_exfiltration_investigations_evidence_confidence", "exfiltration_investigations", ["evidence_confidence"])
    op.create_index("ix_exfiltration_investigations_evidence_completeness", "exfiltration_investigations", ["evidence_completeness"])
    op.create_index("ix_exfiltration_investigations_primary_endpoint_id", "exfiltration_investigations", ["primary_endpoint_id"])
    op.create_index("ix_exfiltration_investigations_created_at", "exfiltration_investigations", ["created_at"])
    op.create_index("ix_exfil_inv_status_risk", "exfiltration_investigations", ["status", "risk_score"])
    op.create_index("ix_exfil_inv_created_sev", "exfiltration_investigations", ["created_at", "severity"])

    # 3. Create correlation_records table
    op.create_table(
        "correlation_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=16), nullable=False, server_default="1.0.0"),
        sa.Column("score_contribution", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relationship_type", sa.String(length=32), nullable=False, server_default="temporal"),
        sa.Column("evidence_completeness", sa.String(length=16), nullable=False, server_default="PARTIAL"),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(length=255), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["exfiltration_investigations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_correlation_records_investigation_id", "correlation_records", ["investigation_id"])
    op.create_index("ix_correlation_records_rule_id", "correlation_records", ["rule_id"])

    # 4. Create investigation_evidence_links table
    op.create_table(
        "investigation_evidence_links",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("evidence_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_provenance", sa.String(length=32), nullable=False, server_default="OBSERVED"),
        sa.Column("relationship_nature", sa.String(length=32), nullable=False, server_default="temporal"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["exfiltration_investigations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigation_evidence_links_investigation_id", "investigation_evidence_links", ["investigation_id"])
    op.create_index("ix_investigation_evidence_links_evidence_type", "investigation_evidence_links", ["evidence_type"])
    op.create_index("ix_investigation_evidence_links_evidence_id", "investigation_evidence_links", ["evidence_id"])
    op.create_index("ix_evidence_links_inv_time", "investigation_evidence_links", ["investigation_id", "timestamp"])


def downgrade() -> None:
    op.drop_table("investigation_evidence_links")
    op.drop_table("correlation_records")
    op.drop_table("exfiltration_investigations")
    op.drop_table("transfer_events")
