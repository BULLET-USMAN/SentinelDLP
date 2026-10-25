"""DNS Anomaly Detection Rules for SentinelDLP (Phase 7).

Implements:
- NET-004: Unusual DNS Query Frequency
- NET-005: DNS Query Pattern Anomalies (Long / High-Entropy Names)

Forensic Constraint:
- Never asserts confirmed DNS tunneling based solely on length or entropy.
- Explicitly flags findings as observable pattern anomalies requiring investigation.
"""

from collections import defaultdict
import math
from typing import Any, Dict, List, Optional
from app.network.config import (
    THRESHOLD_DNS_BURST_COUNT,
    THRESHOLD_DNS_NAME_LENGTH,
    THRESHOLD_DNS_SHANNON_ENTROPY,
)
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


class UnusualDNSFrequencyRule(BaseNetworkRule):
    """NET-004: Detects unusually high DNS request rates from a single source."""

    rule_id = "NET-004"
    name = "Unusual DNS Query Frequency"
    version = "1.0.0"
    description = (
        f"Identifies high-frequency DNS query bursts (>={THRESHOLD_DNS_BURST_COUNT} queries) "
        "from a single source endpoint in the correlation window."
    )
    severity_impact = "MEDIUM"
    score_contribution = 20
    required_events = ["DNS"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        queries_by_src: Dict[str, List[str]] = defaultdict(list)
        for e in context.dns_events:
            if e.dns_query:
                queries_by_src[e.source_ip].append(e.id)

        burst_sources = {src: ids for src, ids in queries_by_src.items() if len(ids) >= THRESHOLD_DNS_BURST_COUNT}
        if not burst_sources:
            return None

        primary_src, event_ids = max(burst_sources.items(), key=lambda item: len(item[1]))
        count = len(event_ids)

        explanation = (
            f"Source IP {primary_src} executed {count} DNS queries within {context.window_minutes}m window "
            f"(threshold: {THRESHOLD_DNS_BURST_COUNT}). May indicate service discovery, scanning, or DGA activity."
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
                "dns_query_count": count,
                "threshold": THRESHOLD_DNS_BURST_COUNT,
            },
            evidence_completeness="COMPLETE",
            relationship_type=self.relationship_type,
            linked_event_ids=event_ids[:10],
        )


class DNSQueryPatternAnomaliesRule(BaseNetworkRule):
    """NET-005: Identifies unusually long or high-entropy DNS queries."""

    rule_id = "NET-005"
    name = "DNS Query Pattern Anomalies"
    version = "1.0.0"
    description = (
        "Identifies unusually long (>50 chars) or high-entropy (>3.8) DNS domain names. "
        "Note: Does not claim confirmed DNS tunneling based solely on pattern heuristics."
    )
    severity_impact = "HIGH"
    score_contribution = 35
    required_events = ["DNS"]
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        anomalous_events: List[Tuple[Any, str, float]] = []

        for e in context.dns_events:
            q = e.dns_query
            if not q or "." not in q:
                continue

            subdomain = q.split(".")[0]
            entropy = calculate_entropy(subdomain)
            is_long = len(q) >= THRESHOLD_DNS_NAME_LENGTH
            is_high_entropy = entropy >= THRESHOLD_DNS_SHANNON_ENTROPY and len(subdomain) >= 12

            if is_long or is_high_entropy:
                reason = []
                if is_long:
                    reason.append(f"length {len(q)} >= {THRESHOLD_DNS_NAME_LENGTH}")
                if is_high_entropy:
                    reason.append(f"entropy {entropy:.2f} >= {THRESHOLD_DNS_SHANNON_ENTROPY}")
                anomalous_events.append((e, ", ".join(reason), entropy))

        if not anomalous_events:
            return None

        primary_evt, reason_str, ent_val = anomalous_events[0]

        explanation = (
            f"Observed anomalous DNS query '{primary_evt.dns_query}' from {primary_evt.source_ip} "
            f"({reason_str}). Heuristic anomaly detected; does not confirm tunneling without payload proof."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "query": primary_evt.dns_query,
                "source_ip": primary_evt.source_ip,
                "reason": reason_str,
                "entropy": round(ent_val, 2),
                "total_anomalies_in_window": len(anomalous_events),
            },
            evidence_completeness="COMPLETE",
            relationship_type=self.relationship_type,
            linked_event_ids=[evt[0].id for evt in anomalous_events[:5]],
        )
