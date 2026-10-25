"""Investigation Lifecycle & Triage Management Service (Phase 6).

Implements analyst triage workflows, status updates, auditing, and statistical KPIs.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from app.exfiltration.confidence import calculate_exfiltration_risk_and_confidence
from app.exfiltration.provenance import (
    EvidenceCompleteness,
    EvidenceConfidence,
    InvestigationStatus,
)
from app.exfiltration.rules.base import ExfiltrationRuleMatch
from app.exfiltration.schemas import ExfiltrationStatisticsResponse, InvestigationStatusUpdate
from app.models.exfiltration import (
    CorrelationRecord,
    ExfiltrationInvestigation,
    InvestigationEvidenceLink,
    TransferEvent,
)
from app.risk.severity import RiskSeverity


class InvestigationService:
    """Service layer for querying and managing ExfiltrationInvestigation records."""

    @staticmethod
    def create_investigation_from_matches(
        db: Session,
        matches: List[ExfiltrationRuleMatch],
        window_minutes: int,
        endpoint_id: Optional[str] = "endpoint-alpha-01",
    ) -> ExfiltrationInvestigation:
        """Create a new ExfiltrationInvestigation with linked rules and evidence."""
        # Calculate quantitative score & confidence
        scores = [m.score_contribution for m in matches]
        rule_ids = {m.rule_id for m in matches}
        has_sensitive = "EXFIL-001" in rule_ids or "EXFIL-002" in rule_ids or "EXFIL-007" in rule_ids
        has_archive = "EXFIL-002" in rule_ids or "EXFIL-003" in rule_ids or "EXFIL-007" in rule_ids
        has_transfer = any(r in rule_ids for r in ("EXFIL-003", "EXFIL-004", "EXFIL-005", "EXFIL-006", "EXFIL-007"))
        has_unfamiliar = "EXFIL-005" in rule_ids

        risk_score, severity, confidence, completeness = calculate_exfiltration_risk_and_confidence(
            rule_score_contributions=scores,
            has_sensitive_activity=has_sensitive,
            has_archive_event=has_archive,
            has_outbound_transfer=has_transfer,
            has_unfamiliar_destination=has_unfamiliar,
        )

        # Primary rule gives headline
        primary_match = max(matches, key=lambda m: m.score_contribution)
        title = f"{primary_match.rule_name} (Risk Score: {risk_score})"
        description = (
            f"Correlation engine identified {len(matches)} suspicious exfiltration signal(s) "
            f"within a {window_minutes}-minute evaluation window. Primary finding: {primary_match.summary}"
        )

        investigation = ExfiltrationInvestigation(
            title=title,
            description=description,
            status=InvestigationStatus.OPEN.value,
            risk_score=risk_score,
            severity=severity.value,
            evidence_confidence=confidence.value,
            evidence_completeness=completeness.value,
            primary_endpoint_id=endpoint_id,
            correlation_window_minutes=window_minutes,
            rules_triggered_count=len(matches),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(investigation)
        db.flush()

        # Add Correlation Records
        for m in matches:
            rec = CorrelationRecord(
                investigation_id=investigation.id,
                rule_id=m.rule_id,
                rule_name=m.rule_name,
                rule_version=m.rule_version,
                score_contribution=m.score_contribution,
                relationship_type=m.relationship_type.value,
                evidence_completeness=m.evidence_completeness.value,
                matched_at=datetime.now(timezone.utc),
                summary=m.summary,
                details_json=json.dumps(m.details) if m.details else None,
            )
            db.add(rec)

            # Add Evidence Links
            for ev in m.linked_evidence:
                link = InvestigationEvidenceLink(
                    investigation_id=investigation.id,
                    evidence_type=ev["evidence_type"],
                    evidence_id=ev["evidence_id"],
                    evidence_provenance=ev.get("evidence_provenance", "OBSERVED"),
                    relationship_nature=ev.get("relationship_nature", "temporal"),
                    timestamp=ev["timestamp"],
                    description=ev["description"],
                    metadata_json=json.dumps(ev.get("metadata", {})),
                )
                db.add(link)

        db.commit()
        db.refresh(investigation)
        return investigation

    @staticmethod
    def get_investigation(db: Session, investigation_id: str) -> Optional[ExfiltrationInvestigation]:
        """Fetch investigation with preloaded correlation records and evidence links."""
        return (
            db.query(ExfiltrationInvestigation)
            .options(
                joinedload(ExfiltrationInvestigation.correlation_records),
                joinedload(ExfiltrationInvestigation.evidence_links),
            )
            .filter(ExfiltrationInvestigation.id == investigation_id)
            .first()
        )

    @staticmethod
    def list_investigations(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[ExfiltrationInvestigation], int]:
        """Filterable, paginated query of investigations."""
        query = db.query(ExfiltrationInvestigation)
        if status:
            query = query.filter(ExfiltrationInvestigation.status == status.upper())
        if severity:
            query = query.filter(ExfiltrationInvestigation.severity == severity.upper())
        if confidence:
            query = query.filter(ExfiltrationInvestigation.evidence_confidence == confidence.upper())

        total = query.count()
        results = (
            query.order_by(ExfiltrationInvestigation.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return results, total

    @staticmethod
    def update_status(
        db: Session,
        investigation_id: str,
        payload: InvestigationStatusUpdate,
    ) -> Optional[ExfiltrationInvestigation]:
        """Update triage lifecycle status, assigned analyst, and investigation notes."""
        inv = db.query(ExfiltrationInvestigation).filter(ExfiltrationInvestigation.id == investigation_id).first()
        if not inv:
            return None

        inv.status = payload.status.value
        inv.updated_at = datetime.now(timezone.utc)
        if payload.assigned_analyst:
            inv.assigned_analyst = payload.assigned_analyst
        if payload.notes:
            existing = inv.investigation_notes or ""
            timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            note_entry = f"[{timestamp_str}] ({payload.status.value}) {payload.notes}\n"
            inv.investigation_notes = existing + note_entry

        if payload.status in (
            InvestigationStatus.RESOLVED,
            InvestigationStatus.FALSE_POSITIVE,
            InvestigationStatus.INCONCLUSIVE,
        ):
            inv.resolved_at = datetime.now(timezone.utc)
        else:
            inv.resolved_at = None

        db.commit()
        db.refresh(inv)
        return inv

    @staticmethod
    def get_statistics(db: Session) -> ExfiltrationStatisticsResponse:
        """Compute live telemetry summary metrics."""
        total = db.query(ExfiltrationInvestigation).count()
        open_count = db.query(ExfiltrationInvestigation).filter(
            ExfiltrationInvestigation.status.in_(["OPEN", "INVESTIGATING", "ACKNOWLEDGED"])
        ).count()
        critical_count = db.query(ExfiltrationInvestigation).filter(
            ExfiltrationInvestigation.severity == RiskSeverity.CRITICAL.value
        ).count()
        high_count = db.query(ExfiltrationInvestigation).filter(
            ExfiltrationInvestigation.severity == RiskSeverity.HIGH.value
        ).count()
        simulated_transfers = db.query(TransferEvent).filter(TransferEvent.is_simulated.is_(True)).count()
        avg_score_res = db.query(func.avg(ExfiltrationInvestigation.risk_score)).scalar()
        avg_score = float(avg_score_res) if avg_score_res is not None else 0.0

        return ExfiltrationStatisticsResponse(
            total_investigations=total,
            open_investigations=open_count,
            critical_investigations=critical_count,
            high_investigations=high_count,
            simulated_transfer_count=simulated_transfers,
            rules_active_count=8,
            average_risk_score=round(avg_score, 1),
        )
