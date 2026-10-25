"""NET-007: Suricata Signature Alert Normalization (Phase 7).

Normalizes Suricata EVE IDS signature alerts and prepares correlated findings for SentinelDLP alert system.
"""

from typing import Any, Dict, List, Optional
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


class SuricataSignatureAlertRule(BaseNetworkRule):
    """NET-007: Evaluates Suricata signature alerts and surfaces high-confidence matches."""

    rule_id = "NET-007"
    name = "Suricata Signature Alert"
    version = "1.0.0"
    description = (
        "Normalizes Suricata IDS signature alerts and routes findings to SentinelDLP's "
        "alert triage pipeline without assuming unconfirmed intrusions."
    )
    severity_impact = "HIGH"
    score_contribution = 40
    required_events = ["ALERT"]
    relationship_type = "verified"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        if not context.ids_alerts:
            return None

        # Pick the most severe alert
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_alerts = sorted(
            context.ids_alerts,
            key=lambda e: severity_order.get((e.alert_severity or "MEDIUM").upper(), 2),
            reverse=True,
        )

        primary = sorted_alerts[0]
        sig_name = primary.alert_signature or "Suricata IDS Alert"
        sev = primary.alert_severity or "HIGH"

        explanation = (
            f"Suricata sensor '{primary.sensor_id}' triggered signature '{sig_name}' "
            f"between {primary.source_ip} and {primary.destination_ip}:{primary.destination_port or ''} "
            f"({primary.transport_protocol}). Mapped to severity: {sev}."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=40 if sev in ("CRITICAL", "HIGH") else 20,
            severity_impact=sev,
            explanation=explanation,
            evidence={
                "signature": sig_name,
                "sensor_id": primary.sensor_id,
                "source_ip": primary.source_ip,
                "destination_ip": primary.destination_ip,
                "destination_port": primary.destination_port,
                "protocol": primary.transport_protocol,
                "total_alerts_in_window": len(context.ids_alerts),
            },
            evidence_completeness="COMPLETE",
            relationship_type="verified",
            linked_event_ids=[a.id for a in sorted_alerts[:5]],
        )
