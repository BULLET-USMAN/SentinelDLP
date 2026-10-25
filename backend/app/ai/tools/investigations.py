"""Read-only exfiltration correlation and investigation tools."""

from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from app.models.exfiltration import (
    ExfiltrationInvestigation,
    InvestigationEvidenceLink,
    CorrelationRecord,
    TransferEvent,
)
from app.ai.security.sanitization import sanitize_evidence_dict


def get_investigation_timeline(db: Session, investigation_id: str) -> Optional[List[Dict[str, Any]]]:
    """Retrieve synthesized multi-stage forensic timeline for an investigation."""
    if not investigation_id:
        return None

    inv = db.query(ExfiltrationInvestigation).filter(ExfiltrationInvestigation.id == investigation_id.strip()).first()
    if not inv:
        return None

    # Retrieve all evidence links
    evidence_links = (
        db.query(InvestigationEvidenceLink)
        .filter(InvestigationEvidenceLink.investigation_id == inv.id)
        .order_by(InvestigationEvidenceLink.timestamp.asc())
        .all()
    )

    timeline: List[Dict[str, Any]] = []
    for link in evidence_links:
        timeline.append({
            "evidence_id": link.evidence_id,
            "evidence_type": link.evidence_type,
            "evidence_provenance": link.evidence_provenance,
            "relationship_nature": link.relationship_nature,
            "timestamp": link.timestamp.isoformat() if link.timestamp else None,
            "description": link.description,
        })

    return [sanitize_evidence_dict(item) for item in timeline]


def get_exfiltration_evidence(db: Session, investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve summary of exfiltration investigation metadata, risk score, and triggered correlation rules."""
    if not investigation_id:
        return None

    inv = db.query(ExfiltrationInvestigation).filter(ExfiltrationInvestigation.id == investigation_id.strip()).first()
    if not inv:
        return None

    rules = (
        db.query(CorrelationRecord)
        .filter(CorrelationRecord.investigation_id == inv.id)
        .all()
    )
    rules_data = [
        {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "score_contribution": r.score_contribution,
            "relationship_type": r.relationship_type,
            "evidence_completeness": r.evidence_completeness,
            "summary": r.summary,
        }
        for r in rules
    ]

    data = {
        "investigation_id": inv.id,
        "title": inv.title,
        "description": inv.description,
        "status": inv.status,
        "risk_score": inv.risk_score,
        "severity": inv.severity,
        "evidence_confidence": inv.evidence_confidence,
        "evidence_completeness": inv.evidence_completeness,
        "correlation_window_minutes": inv.correlation_window_minutes,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "assigned_analyst": inv.assigned_analyst,
        "investigation_notes": inv.investigation_notes,
        "rules_triggered": rules_data,
    }
    return sanitize_evidence_dict(data)
