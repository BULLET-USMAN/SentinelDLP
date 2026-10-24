"""File scanner schema for SentinelDLP Phase 2.

Revision ID: 0002_file_scanner_schema
Revises: 0001_initial_schema
Create Date: 2026-10-24 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_file_scanner_schema"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create scan_jobs table
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("root_path", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("files_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_bytes_processed", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_jobs_root_id"), "scan_jobs", ["root_id"], unique=False)
    op.create_index(op.f("ix_scan_jobs_status"), "scan_jobs", ["status"], unique=False)
    op.create_index(op.f("ix_scan_jobs_started_at"), "scan_jobs", ["started_at"], unique=False)

    # 2. Create scanned_files table
    op.create_table(
        "scanned_files",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_job_id", sa.String(length=36), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("relative_path", sa.String(length=1024), nullable=False),
        sa.Column("file_extension", sa.String(length=32), nullable=False),
        sa.Column("detected_type", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sha256_hash", sa.String(length=64), nullable=True),
        sa.Column("scan_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("type_mismatch", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scanned_files_scan_job_id"), "scanned_files", ["scan_job_id"], unique=False)
    op.create_index(op.f("ix_scanned_files_filename"), "scanned_files", ["filename"], unique=False)
    op.create_index(op.f("ix_scanned_files_relative_path"), "scanned_files", ["relative_path"], unique=False)
    op.create_index(op.f("ix_scanned_files_file_extension"), "scanned_files", ["file_extension"], unique=False)
    op.create_index(op.f("ix_scanned_files_detected_type"), "scanned_files", ["detected_type"], unique=False)
    op.create_index(op.f("ix_scanned_files_sha256_hash"), "scanned_files", ["sha256_hash"], unique=False)
    op.create_index(op.f("ix_scanned_files_status"), "scanned_files", ["status"], unique=False)
    op.create_index(op.f("ix_scanned_files_type_mismatch"), "scanned_files", ["type_mismatch"], unique=False)
    op.create_index("ix_scanned_files_job_status", "scanned_files", ["scan_job_id", "status"], unique=False)
    op.create_index("ix_scanned_files_job_type", "scanned_files", ["scan_job_id", "detected_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scanned_files_job_type", table_name="scanned_files")
    op.drop_index("ix_scanned_files_job_status", table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_type_mismatch"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_status"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_sha256_hash"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_detected_type"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_file_extension"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_relative_path"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_filename"), table_name="scanned_files")
    op.drop_index(op.f("ix_scanned_files_scan_job_id"), table_name="scanned_files")
    op.drop_table("scanned_files")

    op.drop_index(op.f("ix_scan_jobs_started_at"), table_name="scan_jobs")
    op.drop_index(op.f("ix_scan_jobs_status"), table_name="scan_jobs")
    op.drop_index(op.f("ix_scan_jobs_root_id"), table_name="scan_jobs")
    op.drop_table("scan_jobs")
