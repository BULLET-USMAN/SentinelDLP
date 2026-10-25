"""Connection Frequency and Port Dispersion Rules (Phase 7).

Implements:
- NET-002: Repeated Connection Attempts
- NET-003: Multi-Port Connection Activity
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional
from app.network.config import THRESHOLD_CONNECTION_BURST_COUNT, THRESHOLD_MULTI_PORT_COUNT
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


class RepeatedConnectionAttemptsRule(BaseNetworkRule):
    """NET-002: Detects unusually high connection frequency from a single source within the window."""

    rule_id = "NET-002"
    name = "Repeated Connection Attempts"
    version = "1.0.0"
    description = (
        f"Identifies high-frequency connection bursts (>={THRESHOLD_CONNECTION_BURST_COUNT} connections) "
        "originating from a single source endpoint in the correlation window."
    )
    severity_impact = "MEDIUM"
    score_contribution = 20
    required_events = ["CONNECTION", "FLOW"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        counts_by_src: Dict[str, List[str]] = defaultdict(list)
        for e in context.connections:
            counts_by_src[e.source_ip].append(e.id)

        burst_sources = {src: ids for src, ids in counts_by_src.items() if len(ids) >= THRESHOLD_CONNECTION_BURST_COUNT}
        if not burst_sources:
            return None

        primary_src, event_ids = max(burst_sources.items(), key=lambda item: len(item[1]))
        count = len(event_ids)

        explanation = (
            f"Source IP {primary_src} initiated {count} network connections within "
            f"a {context.window_minutes}m window (threshold: {THRESHOLD_CONNECTION_BURST_COUNT}). "
            "Suggestive of iterative polling, automated transfers, or beaconing."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "source_ip": primary_src,
                "connection_count": count,
                "threshold": THRESHOLD_CONNECTION_BURST_COUNT,
                "window_minutes": context.window_minutes,
            },
            evidence_completeness="COMPLETE",
            relationship_type=self.relationship_type,
            linked_event_ids=event_ids[:10],
        )


class MultiPortConnectionRule(BaseNetworkRule):
    """NET-003: Detects a single source endpoint connecting to an unusually large number of distinct ports."""

    rule_id = "NET-003"
    name = "Multi-Port Connection Activity"
    version = "1.0.0"
    description = (
        f"Identifies sources contacting an unusually large number of destination ports "
        f"(>={THRESHOLD_MULTI_PORT_COUNT} distinct ports). Does not claim malicious scanning without intent."
    )
    severity_impact = "LOW"
    score_contribution = 15
    required_events = ["CONNECTION", "FLOW"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        ports_by_src: Dict[str, Dict[int, str]] = defaultdict(dict)
        for e in context.connections:
            if e.destination_port:
                ports_by_src[e.source_ip][e.destination_port] = e.id

        multi_port_sources = {
            src: port_map for src, port_map in ports_by_src.items()
            if len(port_map) >= THRESHOLD_MULTI_PORT_COUNT
        }
        if not multi_port_sources:
            return None

        primary_src, port_map = max(multi_port_sources.items(), key=lambda item: len(item[1]))
        distinct_count = len(port_map)

        explanation = (
            f"Source IP {primary_src} contacted {distinct_count} distinct destination ports "
            f"in {context.window_minutes}m window (threshold: {THRESHOLD_MULTI_PORT_COUNT}). "
            "Note: Telemetry flags volume dispersion without assuming malicious intent."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "source_ip": primary_src,
                "distinct_ports_count": distinct_count,
                "sample_ports": list(port_map.keys())[:10],
            },
            evidence_completeness="COMPLETE",
            relationship_type=self.relationship_type,
            linked_event_ids=list(port_map.values())[:10],
        )
