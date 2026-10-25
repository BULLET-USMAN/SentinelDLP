"""Network telemetry, sensor, and IDS event schema for SentinelDLP Phase 7.

Revision ID: 0007_network_monitoring
Revises: 0006_exfiltration_correlation
Create Date: 2026-10-25 16:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_network_monitoring"
down_revision: Union[str, None] = "0006_exfiltration_correlation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create network_sensors table
    op.create_table(
        "network_sensors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sensor_id", sa.String(length=64), nullable=False),
        sa.Column("technology", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("configuration_reference", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_import_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("coverage_gap_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sensor_id"),
    )
    op.create_index("ix_network_sensors_sensor_id", "network_sensors", ["sensor_id"], unique=True)
    op.create_index("ix_network_sensors_technology", "network_sensors", ["technology"])
    op.create_index("ix_network_sensors_health_status", "network_sensors", ["health_status"])

    # 2. Create network_events table
    op.create_table(
        "network_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sensor_id", sa.String(length=64), nullable=False),
        sa.Column("source_technology", sa.String(length=32), nullable=False),
        sa.Column("original_event_id", sa.String(length=128), nullable=True),
        sa.Column("event_category", sa.String(length=32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("transport_protocol", sa.String(length=16), nullable=False, server_default="TCP"),
        sa.Column("application_protocol", sa.String(length=32), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=False, server_default="OUTBOUND"),
        sa.Column("connection_duration_seconds", sa.Float(), nullable=True),
        sa.Column("bytes_source_to_dest", sa.BigInteger(), nullable=True),
        sa.Column("bytes_dest_to_source", sa.BigInteger(), nullable=True),
        sa.Column("total_bytes", sa.BigInteger(), nullable=True),
        sa.Column("packets_total", sa.Integer(), nullable=True),
        sa.Column("dns_query", sa.String(length=255), nullable=True),
        sa.Column("dns_query_type", sa.String(length=16), nullable=True),
        sa.Column("dns_response_code", sa.String(length=32), nullable=True),
        sa.Column("tls_sni", sa.String(length=255), nullable=True),
        sa.Column("tls_version", sa.String(length=32), nullable=True),
        sa.Column("http_method", sa.String(length=16), nullable=True),
        sa.Column("http_host", sa.String(length=255), nullable=True),
        sa.Column("http_uri_stem", sa.String(length=512), nullable=True),
        sa.Column("alert_signature", sa.String(length=255), nullable=True),
        sa.Column("alert_severity", sa.String(length=16), nullable=True),
        sa.Column("evidence_provenance", sa.String(length=32), nullable=False, server_default="IMPORTED"),
        sa.Column("capture_completeness", sa.String(length=16), nullable=False, server_default="COMPLETE"),
        sa.Column("is_simulated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("processing_status", sa.String(length=32), nullable=False, server_default="processed"),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["network_sensors.sensor_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_events_sensor_id", "network_events", ["sensor_id"])
    op.create_index("ix_network_events_source_technology", "network_events", ["source_technology"])
    op.create_index("ix_network_events_original_event_id", "network_events", ["original_event_id"])
    op.create_index("ix_network_events_event_category", "network_events", ["event_category"])
    op.create_index("ix_network_events_timestamp", "network_events", ["timestamp"])
    op.create_index("ix_network_events_source_ip", "network_events", ["source_ip"])
    op.create_index("ix_network_events_destination_ip", "network_events", ["destination_ip"])
    op.create_index("ix_network_events_destination_port", "network_events", ["destination_port"])
    op.create_index("ix_network_events_transport_protocol", "network_events", ["transport_protocol"])
    op.create_index("ix_network_events_application_protocol", "network_events", ["application_protocol"])
    op.create_index("ix_network_events_direction", "network_events", ["direction"])
    op.create_index("ix_network_events_total_bytes", "network_events", ["total_bytes"])
    op.create_index("ix_network_events_dns_query", "network_events", ["dns_query"])
    op.create_index("ix_network_events_tls_sni", "network_events", ["tls_sni"])
    op.create_index("ix_network_events_http_host", "network_events", ["http_host"])
    op.create_index("ix_network_events_alert_signature", "network_events", ["alert_signature"])
    op.create_index("ix_network_events_alert_severity", "network_events", ["alert_severity"])
    op.create_index("ix_network_events_evidence_provenance", "network_events", ["evidence_provenance"])
    op.create_index("ix_net_events_time_bytes", "network_events", ["timestamp", "total_bytes"])
    op.create_index("ix_net_events_src_dst", "network_events", ["source_ip", "destination_ip"])
    op.create_index("ix_net_events_sensor_orig", "network_events", ["sensor_id", "original_event_id"])
    op.create_index("ix_net_events_category_time", "network_events", ["event_category", "timestamp"])

    # 3. Create network_alert_references table
    op.create_table(
        "network_alert_references",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("network_event_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=True),
        sa.Column("signature_name", sa.String(length=255), nullable=False),
        sa.Column("suricata_sid", sa.Integer(), nullable=True),
        sa.Column("severity_mapping", sa.String(length=16), nullable=False),
        sa.Column("evidence_provenance", sa.String(length=32), nullable=False, server_default="IMPORTED"),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["network_event_id"],
            ["network_events.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["security_alerts.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_alert_references_network_event_id", "network_alert_references", ["network_event_id"])
    op.create_index("ix_network_alert_references_alert_id", "network_alert_references", ["alert_id"])
    op.create_index("ix_network_alert_references_signature_name", "network_alert_references", ["signature_name"])
    op.create_index("ix_network_alert_references_suricata_sid", "network_alert_references", ["suricata_sid"])
    op.create_index("ix_network_alert_references_severity_mapping", "network_alert_references", ["severity_mapping"])

    # 4. Create network_ingestion_jobs table
    op.create_table(
        "network_ingestion_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sensor_id", sa.String(length=64), nullable=False),
        sa.Column("source_format", sa.String(length=32), nullable=False),
        sa.Column("file_path", sa.String(length=512), nullable=True),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completion_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["sensor_id"],
            ["network_sensors.sensor_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_ingestion_jobs_sensor_id", "network_ingestion_jobs", ["sensor_id"])
    op.create_index("ix_network_ingestion_jobs_source_format", "network_ingestion_jobs", ["source_format"])
    op.create_index("ix_network_ingestion_jobs_status", "network_ingestion_jobs", ["status"])

    # 5. Create network_baselines table
    op.create_table(
        "network_baselines",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("baseline_id", sa.String(length=64), nullable=False),
        sa.Column("applicable_source_scope", sa.String(length=64), nullable=False, server_default="GLOBAL"),
        sa.Column("metric", sa.String(length=64), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("baseline_id"),
    )
    op.create_index("ix_network_baselines_baseline_id", "network_baselines", ["baseline_id"], unique=True)
    op.create_index("ix_network_baselines_metric", "network_baselines", ["metric"])

    # 6. Create threat_intel_indicators table
    op.create_table(
        "threat_intel_indicators",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("indicator_value", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False, server_default="SUSPICIOUS"),
        sa.Column("source_feed", sa.String(length=64), nullable=False, server_default="LOCAL_POLICY"),
        sa.Column("confidence", sa.String(length=16), nullable=False, server_default="HIGH"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_intel_indicators_indicator_type", "threat_intel_indicators", ["indicator_type"])
    op.create_index("ix_threat_intel_indicators_indicator_value", "threat_intel_indicators", ["indicator_value"])
    op.create_index("ix_threat_intel_indicators_category", "threat_intel_indicators", ["category"])
    op.create_index("ix_intel_type_val", "threat_intel_indicators", ["indicator_type", "indicator_value"])


def downgrade() -> None:
    op.drop_table("threat_intel_indicators")
    op.drop_table("network_baselines")
    op.drop_table("network_ingestion_jobs")
    op.drop_table("network_alert_references")
    op.drop_table("network_events")
    op.drop_table("network_sensors")
