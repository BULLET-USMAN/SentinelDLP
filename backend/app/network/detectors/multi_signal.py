"""NET-010: Multi-Signal Network Investigation Rule (Phase 7).

Combines multiple independent network indicators (e.g. anomalous DNS + large outbound flow +
unfamiliar destination or IDS alert) within the correlation window.
"""

from typing import Any, Dict, List, Optional
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch
from app.network.threat_intel import ThreatIntelService


class MultiSignalNetworkRule(BaseNetworkRule):
    """NET-010: Synthesizes multi-stage network indicators into a high-priority incident."""

    rule_id = "NET-010"
    name = "Multi-Signal Network Investigation"
    version = "1.0.0"
    description = (
        "Combines multiple independent network indicators (anomalous DNS, large outbound transfer, "
        "and unfamiliar destination or Suricata alert) into a high-confidence incident."
    )
    severity_impact = "CRITICAL"
    score_contribution = 50
    required_events = ["CONNECTION", "DNS", "ALERT"]
    relationship_type = "circumstantial"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        has_anomalous_dns = any(len(e.dns_query or "") > 40 for e in context.dns_events)
        has_large_flow = any((e.total_bytes or 0) >= 5 * 1024 * 1024 for e in context.connections)
        has_alert = bool(context.ids_alerts)

        unfamiliar_conns = [
            e for e in context.connections
            if not ThreatIntelService.is_approved_destination(e.tls_sni or e.http_host or e.destination_ip, db=context.db)
        ]
        has_unfamiliar = bool(unfamiliar_conns)

        # Trigger if at least 3 distinct indicator types are present
        signals_count = sum([
            1 if has_anomalous_dns else 0,
            1 if has_large_flow else 0,
            1 if has_alert else 0,
            1 if has_unfamiliar else 0,
        ])

        if signals_count < 3:
            return None

        primary_flow = max(context.connections, key=lambda c: c.total_bytes or 0) if context.connections else None
        target = primary_flow.destination_ip if primary_flow else "external"

        explanation = (
            f"Multi-signal network attack sequence correlated: observed {signals_count} distinct "
            f"telemetry indicators (large flow, unfamiliar destination, DNS anomaly/IDS alert) "
            f"converging on {target} within a {context.window_minutes}m window."
        )

        linked_ids = []
        if primary_flow:
            linked_ids.append(primary_flow.id)
        if context.ids_alerts:
            linked_ids.append(context.ids_alerts[0].id)
        if context.dns_events:
            linked_ids.append(context.dns_events[0].id)

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "signals_count": signals_count,
                "has_anomalous_dns": has_anomalous_dns,
                "has_large_flow": has_large_flow,
                "has_alert": has_alert,
                "has_unfamiliar": has_unfamiliar,
                "primary_target": target,
            },
            evidence_completeness="COMPLETE",
            relationship_type="circumstantial",
            linked_event_ids=linked_ids,
        )
