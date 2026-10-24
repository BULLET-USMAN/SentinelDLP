"""File activity monitoring schema for SentinelDLP Phase 4.

Revision ID: 0004_file_activity_monitoring
Revises: 0003_sensitive_data_engine
Create Date: 2026-10-24 17:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_file_activity_monitoring"
down_revision: Union[str, None] = "0003_sensitive_data_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create monitoring_configurations table
    op.create_table(
        "monitoring_configurations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("root_path", sa.String(length=512), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("recursive", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("excluded_patterns", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("root_id"),
    )
    op.create_index(op.f("ix_monitoring_configurations_root_id"), "monitoring_configurations", ["root_id"], unique=True)

    # 2. Create monitoring_sessions table
    op.create_table(
        "monitoring_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed_event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("deduplicated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queue_overflow_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_monitoring_sessions_root_id"), "monitoring_sessions", ["root_id"], unique=False)
    op.create_index(op.f("ix_monitoring_sessions_status"), "monitoring_sessions", ["status"], unique=False)

    # 3. Create file_activity_events table
    op.create_table(
        "file_activity_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("monitoring_config_id", sa.String(length=36), nullable=True),
        sa.Column("root_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("is_directory", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("relative_path", sa.String(length=1024), nullable=False),
        sa.Column("previous_relative_path", sa.String(length=1024), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("associated_file_id", sa.String(length=36), nullable=True),
        sa.Column("sensitivity_label", sa.String(length=32), nullable=True),
        sa.Column("file_type", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256_hash", sa.String(length=64), nullable=True),
        sa.Column("event_source", sa.String(length=32), nullable=False, server_default="watchdog"),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["monitoring_config_id"], ["monitoring_configurations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["associated_file_id"], ["scanned_files.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_file_activity_events_monitoring_config_id"), "file_activity_events", ["monitoring_config_id"], unique=False)
    op.create_index(op.f("ix_file_activity_events_root_id"), "file_activity_events", ["root_id"], unique=False)
    op.create_index(op.f("ix_file_activity_events_event_type"), "file_activity_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_file_activity_events_relative_path"), "file_activity_events", ["relative_path"], unique=False)
    op.create_index(op.f("ix_file_activity_events_occurred_at"), "file_activity_events", ["occurred_at"], unique=False)
    op.create_index(op.f("ix_file_activity_events_status"), "file_activity_events", ["status"], unique=False)
    op.create_index(op.f("ix_file_activity_events_associated_file_id"), "file_activity_events", ["associated_file_id"], unique=False)
    op.create_index(op.f("ix_file_activity_events_sensitivity_label"), "file_activity_events", ["sensitivity_label"], unique=False)
    op.create_index("ix_activity_events_root_occurred", "file_activity_events", ["root_id", "occurred_at"], unique=False)
    op.create_index("ix_activity_events_type_status", "file_activity_events", ["event_type", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_activity_events_type_status", table_name="file_activity_events")
    op.drop_index("ix_activity_events_root_occurred", table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_sensitivity_label"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_associated_file_id"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_status"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_occurred_at"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_relative_path"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_event_type"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_root_id"), table_name="file_activity_events")
    op.drop_index(op.f("ix_file_activity_events_monitoring_config_id"), table_name="file_activity_events")
    op.drop_table("file_activity_events")

    op.drop_index(op.f("ix_monitoring_sessions_status"), table_name="monitoring_sessions")
    op.drop_index(op.f("ix_monitoring_sessions_root_id"), table_name="monitoring_sessions")
    op.drop_table("monitoring_sessions")

    op.drop_index(op.f("ix_monitoring_configurations_root_id"), table_name="monitoring_configurations")
    op.drop_table("monitoring_configurations")
