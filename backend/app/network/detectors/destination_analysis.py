"""NET-006: Unfamiliar Outbound Destination Analysis (Phase 7).

Flags outbound network destinations outside baseline allowlists or matching local threat intel.
Does not claim unknown destinations are necessarily malicious without corroboration.
"""

from typing import Any, Dict, List, Optional
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch
from app.network.threat_intel import ThreatIntelService


class UnfamiliarDestinationRule(BaseNetworkRule):
    """NET-006: Identifies outbound flows to destinations outside baseline allowlists or matching threat intel."""

    rule_id = "NET-006"
    name = "Unfamiliar Outbound Destination"
    version = "1.0.0"
    description = (
        "Identifies outbound network connections directed toward destinations outside the "
        "authorized baseline allowlist or matching locally imported threat intelligence indicators."
    )
    severity_impact = "HIGH"
    score_contribution = 30
    required_events = ["CONNECTION", "FLOW", "TLS", "HTTP"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        unfamiliar_events = []
        matched_indicators = []

        for e in context.connections:
            # Check host (TLS SNI or HTTP host) or IP
            target_host = e.tls_sni or e.http_host or e.destination_ip

            # Check threat intelligence first
            ind = ThreatIntelService.match_indicator(context.db, destination_ip=e.destination_ip, destination_host=target_host)
            if ind:
                matched_indicators.append((e, ind))
                continue

            # Check allowlist
            if not ThreatIntelService.is_approved_destination(target_host, db=context.db):
                unfamiliar_events.append(e)

        if not matched_indicators and not unfamiliar_events:
            return None

        # Prioritize threat intel matches if any
        if matched_indicators:
            primary_e, primary_ind = matched_indicators[0]
            explanation = (
                f"Outbound connection from {primary_e.source_ip} to {primary_e.destination_ip} "
                f"matched local threat intelligence indicator '{primary_ind.indicator_value}' "
                f"({primary_ind.category}, source: {primary_ind.source_feed})."
            )
            return NetworkRuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                rule_version=self.version,
                score_contribution=40,
                severity_impact="HIGH",
                explanation=explanation,
                evidence={
                    "destination_ip": primary_e.destination_ip,
                    "target_host": primary_e.tls_sni or primary_e.http_host,
                    "indicator_value": primary_ind.indicator_value,
                    "category": primary_ind.category,
                    "confidence": primary_ind.confidence,
                },
                evidence_completeness="COMPLETE",
                relationship_type=self.relationship_type,
                linked_event_ids=[primary_e.id],
            )

        # Baseline unfamiliar destination
        primary = unfamiliar_events[0]
        dest_label = primary.tls_sni or primary.http_host or primary.destination_ip
        explanation = (
            f"Observed outbound connection from {primary.source_ip} to unfamiliar external "
            f"destination '{dest_label}' (port {primary.destination_port or ''}). "
            "Note: Flagged as outside baseline; not asserted as confirmed malicious."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=25,
            severity_impact="MEDIUM",
            explanation=explanation,
            evidence={
                "source_ip": primary.source_ip,
                "destination_ip": primary.destination_ip,
                "destination_host": dest_label,
                "total_bytes": primary.total_bytes,
                "protocol": primary.transport_protocol,
            },
            evidence_completeness="PARTIAL",
            relationship_type=self.relationship_type,
            linked_event_ids=[primary.id],
        )
