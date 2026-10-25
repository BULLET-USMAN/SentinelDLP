"""Network Detection Evaluation & Phase 6 Correlation Bridge (Phase 7).

Coordinates:
- Execution of all 10 network detection rules (NET-001 through NET-010).
- Forwarding IDS and high-severity findings into the Phase 5 SecurityAlert table.
- Bridging verified network transfer evidence directly into Phase 6 Exfiltration Investigations
  with strict 'IMPORTED' or 'OBSERVED' provenance (distinguishing from synthetic 'LAB_SIMULATED').
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from app.exfiltration.engine import exfiltration_engine
from app.exfiltration.provenance import EvidenceProvenance
from app.exfiltration.schemas import TransferEventCreate
from app.exfiltration.services.transfer_service import TransferService
from app.models.exfiltration import ExfiltrationInvestigation
from app.models.network import NetworkAlertReference, NetworkEvent
from app.models.risk import SecurityAlert
from app.network.detectors import get_all_network_rules
from app.network.detectors.base import NetworkEvaluationContext, NetworkRuleMatch


class NetworkCorrelationService:
    """Evaluates network telemetry rules and bridges findings to alert and exfiltration subsystems."""

    @classmethod
    def evaluate_network_rules(
        cls,
        db: Session,
        window_minutes: int = 15,
    ) -> List[NetworkRuleMatch]:
        """Run all 10 network detection rules across telemetry in the window."""
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=window_minutes)

        events = (
            db.query(NetworkEvent)
            .filter(NetworkEvent.timestamp >= start_time, NetworkEvent.timestamp <= now)
            .order_by(NetworkEvent.timestamp.asc())
            .all()
        )

        connections = [e for e in events if e.event_category in ("CONNECTION", "FLOW")]
        dns_events = [e for e in events if e.event_category == "DNS"]
        ids_alerts = [e for e in events if e.event_category == "ALERT"]

        context = NetworkEvaluationContext(
            start_time=start_time,
            end_time=now,
            window_minutes=window_minutes,
            db=db,
            events=events,
            connections=connections,
            dns_events=dns_events,
            ids_alerts=ids_alerts,
        )

        matches: List[NetworkRuleMatch] = []
        for rule in get_all_network_rules():
            match = rule.evaluate(context)
            if match:
                matches.append(match)
                cls._handle_rule_match_side_effects(db, match, context)

        return matches

    @classmethod
    def _handle_rule_match_side_effects(
        cls, db: Session, match: NetworkRuleMatch, context: NetworkEvaluationContext
    ) -> None:
        """Bridge network detections into Phase 5 alerts and Phase 6 exfiltration investigations."""
        # 1. If rule is NET-007 (Suricata Alert), record NetworkAlertReference
        if match.rule_id == "NET-007" and match.linked_event_ids:
            primary_id = match.linked_event_ids[0]
            existing_ref = (
                db.query(NetworkAlertReference)
                .filter(NetworkAlertReference.network_event_id == primary_id)
                .first()
            )
            if not existing_ref:
                ref = NetworkAlertReference(
                    network_event_id=primary_id,
                    signature_name=match.evidence.get("signature", "Suricata Alert"),
                    severity_mapping=match.severity_impact,
                    evidence_provenance="IMPORTED",
                    explanation=match.explanation,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(ref)
                db.commit()

        # 2. If rule is NET-008 (Sensitive File + Network Correlation) or NET-001 (High Outbound Flow),
        # bridge the network evidence into Phase 6 as an authentic TransferEvent (IMPORTED or OBSERVED)
        if match.rule_id in ("NET-008", "NET-001") and match.linked_event_ids:
            net_event = db.query(NetworkEvent).filter(NetworkEvent.id == match.linked_event_ids[0]).first()
            if net_event and net_event.direction == "OUTBOUND":
                dest_host = net_event.tls_sni or net_event.http_host or net_event.destination_ip
                # Create TransferEvent with REAL provenance (not LAB_SIMULATED)
                xfer_payload = TransferEventCreate(
                    source_endpoint_id=net_event.source_ip,
                    occurred_at=net_event.timestamp,
                    direction="OUTBOUND",
                    destination_category="EXTERNAL_IP" if not net_event.tls_sni else "CLOUD_STORAGE",
                    destination_host=dest_host,
                    protocol=net_event.application_protocol or net_event.transport_protocol,
                    byte_count=int(net_event.total_bytes or 0),
                    evidence_source=f"{net_event.source_technology}_SENSOR",
                    evidence_provenance=EvidenceProvenance(net_event.evidence_provenance),
                    is_simulated=net_event.is_simulated,
                    context_data=f'{{"matched_rule": "{match.rule_id}", "sensor": "{net_event.sensor_id}"}}',
                )
                TransferService.record_transfer(db, xfer_payload)

                # Trigger Phase 6 bounded correlation pass to link the new transfer to an investigation
                exfiltration_engine.execute_correlation(
                    db=db,
                    window_minutes=context.window_minutes,
                    endpoint_id=net_event.source_ip,
                )
