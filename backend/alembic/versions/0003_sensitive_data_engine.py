"""Sensitive data engine schema for SentinelDLP Phase 3.

Revision ID: 0003_sensitive_data_engine
Revises: 0002_file_scanner_schema
Create Date: 2026-10-24 16:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0003_sensitive_data_engine"
down_revision: Union[str, None] = "0002_file_scanner_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create file_classifications table
    op.create_table(
        "file_classifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scanned_file_id", sa.String(length=36), nullable=False),
        sa.Column("sensitivity_label", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("classified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("inspection_status", sa.String(length=32), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("highest_confidence", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["scanned_file_id"], ["scanned_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scanned_file_id"),
    )
    op.create_index(op.f("ix_file_classifications_scanned_file_id"), "file_classifications", ["scanned_file_id"], unique=True)
    op.create_index(op.f("ix_file_classifications_sensitivity_label"), "file_classifications", ["sensitivity_label"], unique=False)
    op.create_index(op.f("ix_file_classifications_inspection_status"), "file_classifications", ["inspection_status"], unique=False)

    # 2. Create detection_findings table
    op.create_table(
        "detection_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scanned_file_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scanned_file_id"], ["scanned_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_detection_findings_scanned_file_id"), "detection_findings", ["scanned_file_id"], unique=False)
    op.create_index(op.f("ix_detection_findings_rule_id"), "detection_findings", ["rule_id"], unique=False)
    op.create_index(op.f("ix_detection_findings_category"), "detection_findings", ["category"], unique=False)
    op.create_index(op.f("ix_detection_findings_confidence"), "detection_findings", ["confidence"], unique=False)
    op.create_index("ix_detection_findings_file_category", "detection_findings", ["scanned_file_id", "category"], unique=False)

    # 3. Create scan_detection_summaries table
    op.create_table(
        "scan_detection_summaries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_job_id", sa.String(length=36), nullable=False),
        sa.Column("files_inspected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sensitive_files_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("public_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("internal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidential_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("restricted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("not_assessed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pii_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credential_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("financial_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidential_label_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id"),
    )
    op.create_index(op.f("ix_scan_detection_summaries_scan_job_id"), "scan_detection_summaries", ["scan_job_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_detection_summaries_scan_job_id"), table_name="scan_detection_summaries")
    op.drop_table("scan_detection_summaries")

    op.drop_index("ix_detection_findings_file_category", table_name="detection_findings")
    op.drop_index(op.f("ix_detection_findings_confidence"), table_name="detection_findings")
    op.drop_index(op.f("ix_detection_findings_category"), table_name="detection_findings")
    op.drop_index(op.f("ix_detection_findings_rule_id"), table_name="detection_findings")
    op.drop_index(op.f("ix_detection_findings_scanned_file_id"), table_name="detection_findings")
    op.drop_table("detection_findings")

    op.drop_index(op.f("ix_file_classifications_inspection_status"), table_name="file_classifications")
    op.drop_index(op.f("ix_file_classifications_sensitivity_label"), table_name="file_classifications")
    op.drop_index(op.f("ix_file_classifications_scanned_file_id"), table_name="file_classifications")
    op.drop_table("file_classifications")
