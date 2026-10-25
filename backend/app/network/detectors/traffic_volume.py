"""NET-001: Unusual Outbound Traffic Volume (Phase 7).

Detects outbound network flows exceeding configured volume thresholds or baseline limits.
"""

from typing import Any, Dict, List, Optional
from app.network.config import THRESHOLD_CRITICAL_FLOW_BYTES, THRESHOLD_OUTBOUND_FLOW_BYTES
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


class UnusualOutboundVolumeRule(BaseNetworkRule):
    """NET-001: Triggers on individual or aggregated high-volume outbound network flows."""

    rule_id = "NET-001"
    name = "Unusual Outbound Traffic Volume"
    version = "1.0.0"
    description = (
        "Detects outbound connections exceeding volume thresholds "
        f"(>={THRESHOLD_OUTBOUND_FLOW_BYTES // (1024 * 1024)}MB) within the correlation window."
    )
    severity_impact = "MEDIUM"
    score_contribution = 25
    required_events = ["CONNECTION", "FLOW"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        candidate_events = [
            e for e in context.connections
            if (e.total_bytes or 0) >= THRESHOLD_OUTBOUND_FLOW_BYTES or (e.bytes_source_to_dest or 0) >= THRESHOLD_OUTBOUND_FLOW_BYTES
        ]

        if not candidate_events:
            return None

        largest = max(candidate_events, key=lambda e: e.total_bytes or 0)
        tot_bytes = largest.total_bytes or largest.bytes_source_to_dest or 0
        is_critical = tot_bytes >= THRESHOLD_CRITICAL_FLOW_BYTES

        severity = "HIGH" if is_critical else "MEDIUM"
        score = 40 if is_critical else 25

        explanation = (
            f"Observed outbound network flow of {tot_bytes:,} bytes from {largest.source_ip} "
            f"to {largest.destination_ip}:{largest.destination_port or ''} ({largest.transport_protocol}). "
            f"Exceeds baseline threshold of {THRESHOLD_OUTBOUND_FLOW_BYTES:,} bytes."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=score,
            severity_impact=severity,
            explanation=explanation,
            evidence={
                "source_ip": largest.source_ip,
                "destination_ip": largest.destination_ip,
                "destination_port": largest.destination_port,
                "total_bytes": tot_bytes,
                "protocol": largest.transport_protocol,
                "sensor_id": largest.sensor_id,
            },
            evidence_completeness="COMPLETE",
            relationship_type=self.relationship_type,
            linked_event_ids=[largest.id],
        )
