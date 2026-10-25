"""NET-009: Network Visibility Gap and Sensor Health Rule (Phase 7).

Generates a monitoring coverage warning when network sensors are degraded, offline,
or when packet/log ingestion experiences unexpected dropped telemetry.
"""

from typing import Any, Dict, List, Optional
from app.models.network import NetworkSensor
from app.network.detectors.base import BaseNetworkRule, NetworkEvaluationContext, NetworkRuleMatch


class NetworkVisibilityGapRule(BaseNetworkRule):
    """NET-009: Detects sensor health degradation or unexpected gaps in network monitoring."""

    rule_id = "NET-009"
    name = "Network Visibility Gap"
    version = "1.0.0"
    description = (
        "Generates a diagnostic coverage warning when sensors report errors, ingestion failures, "
        "or degraded health. Does not classify coverage gaps as confirmed attacks."
    )
    severity_impact = "LOW"
    score_contribution = 10
    required_events = []
    relationship_type = "temporal"

    def evaluate(self, context: NetworkEvaluationContext) -> Optional[NetworkRuleMatch]:
        degraded_sensors = (
            context.db.query(NetworkSensor)
            .filter(
                NetworkSensor.health_status.in_(["DEGRADED", "OFFLINE", "VISIBILITY_GAP"]),
                NetworkSensor.enabled.is_(True),
            )
            .all()
        )

        if not degraded_sensors:
            return None

        primary_sensor = degraded_sensors[0]
        reason = primary_sensor.coverage_gap_reason or f"Sensor {primary_sensor.sensor_id} status is {primary_sensor.health_status}"

        explanation = (
            f"Network sensor '{primary_sensor.sensor_id}' ({primary_sensor.technology}) reports "
            f"a visibility gap: {reason}. Diagnostic warning only; telemetry may be incomplete."
        )

        return NetworkRuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.version,
            score_contribution=self.score_contribution,
            severity_impact=self.severity_impact,
            explanation=explanation,
            evidence={
                "sensor_id": primary_sensor.sensor_id,
                "technology": primary_sensor.technology,
                "status": primary_sensor.health_status,
                "reason": primary_sensor.coverage_gap_reason,
            },
            evidence_completeness="INSUFFICIENT",
            relationship_type="temporal",
            linked_event_ids=[],
        )
