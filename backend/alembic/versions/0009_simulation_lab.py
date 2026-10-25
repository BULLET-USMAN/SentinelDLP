"""Cyberattack simulation, detection validation, and security testing laboratory schemas for SentinelDLP Phase 10.

Revision ID: 0009_simulation_lab
Revises: 0008_ai_soc_analyst
Create Date: 2026-10-25 18:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0009_simulation_lab"
down_revision: Union[str, None] = "0008_ai_soc_analyst"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create simulation_runs table
    op.create_table(
        "simulation_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("metrics_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("execution_log_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_simulation_runs_scenario_id"), "simulation_runs", ["scenario_id"], unique=False)
    op.create_index(op.f("ix_simulation_runs_status"), "simulation_runs", ["status"], unique=False)

    # 2. Create simulation_results table
    op.create_table(
        "simulation_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("pass_status", sa.String(length=32), nullable=False, server_default="FAILED"),
        sa.Column("expected_events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actual_events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expected_rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("actual_rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("matched_rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("unmatched_rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("unexpected_rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("expected_alerts_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actual_alerts_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expected_investigations_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actual_investigations_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("precision", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("recall", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("f1_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("false_positive_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("failure_reasons_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["simulation_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_simulation_results_run_id"), "simulation_results", ["run_id"], unique=False)

    # 3. Create simulation_reports table
    op.create_table(
        "simulation_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("markdown_content", sa.Text(), nullable=False),
        sa.Column("execution_metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["simulation_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_simulation_reports_run_id"), "simulation_reports", ["run_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_simulation_reports_run_id"), table_name="simulation_reports")
    op.drop_table("simulation_reports")
    op.drop_index(op.f("ix_simulation_results_run_id"), table_name="simulation_results")
    op.drop_table("simulation_results")
    op.drop_index(op.f("ix_simulation_runs_status"), table_name="simulation_runs")
    op.drop_index(op.f("ix_simulation_runs_scenario_id"), table_name="simulation_runs")
    op.drop_table("simulation_runs")
