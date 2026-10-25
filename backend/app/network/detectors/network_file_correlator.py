"""NET-008: Network and Sensitive File Activity Correlation (Phase 7).

Correlates verified network outbound flows with preceding sensitive filesystem operations.
Maintains forensic modesty: network flows do not prove encrypted payload contents without verification.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from app.models.monitoring import FileActivityEvent
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


class NetworkFileCorrelationRule(BaseNetworkRule):
    """NET-008: Links sensitive file operations with temporally proximate outbound network flows."""

    rule_id = "NET-008"
    name = "Network and Sensitive File Activity Correlation"
    version = "1.0.0"
    description = (
        "Correlates sensitive file activity with subsequent outbound network flows. "
        "Explicitly preserves forensic modesty: network telemetry alone does not prove transferred contents."
    )
    severity_impact = "HIGH"
    score_contribution = 45
    required_events = ["CONNECTION", "FLOW"]
    relationship_type = "circumstantial"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        if not context.connections:
            return None

        # Look for sensitive file activity in database during the correlation window
        file_events = (
            context.db.query(FileActivityEvent)
            .filter(
                FileActivityEvent.occurred_at >= context.start_time,
                FileActivityEvent.occurred_at <= context.end_time,
            )
            .all()
        )

        sensitive_files = [
            f for f in file_events
            if (f.sensitivity_label and f.sensitivity_label.upper() in ("CONFIDENTIAL", "RESTRICTED", "INTERNAL"))
            or any(kw in f.file_path.lower() for kw in ("confidential", "secret", "password", "salary", "classified", "key", "token"))
        ]

        if not sensitive_files:
            return None

        # Correlate with outbound connections having non-trivial byte counts or external destination
        outbound_connections = [
            c for c in context.connections
            if (c.total_bytes or 0) >= 50_000 or c.application_protocol in ("TLS", "HTTP", "SFTP")
        ]
        if not outbound_connections:
            return None

        first_file = sensitive_files[0]
        primary_conn = max(outbound_connections, key=lambda c: c.total_bytes or 0)
        tot_b = primary_conn.total_bytes or primary_conn.bytes_source_to_dest or 0

        dest_label = primary_conn.tls_sni or primary_conn.http_host or primary_conn.destination_ip

        explanation = (
            f"Sensitive file activity on '{first_file.file_path}' was followed by outbound "
            f"network transfer of {tot_b:,} bytes to {dest_label} ({primary_conn.destination_ip}) "
            f"within {context.window_minutes}m window. Correlated relationship is circumstantial; "
            "network flow does not verify payload contents."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "sensitive_file": first_file.file_path,
                "sensitivity_label": first_file.sensitivity_label,
                "destination_host": dest_label,
                "destination_ip": primary_conn.destination_ip,
                "total_bytes": tot_b,
                "sensor_id": primary_conn.sensor_id,
                "provenance": primary_conn.evidence_provenance,
                "payload_contents_verified": False,
            },
            evidence_completeness="PARTIAL",
            relationship_type="circumstantial",
            linked_event_ids=[primary_conn.id],
        )
