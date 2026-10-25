"""Evidence collection and context packaging service for AI investigations."""

from typing import Dict, Any, Set, Tuple
from sqlalchemy.orm import Session

from app.models.exfiltration import ExfiltrationInvestigation, InvestigationEvidenceLink, CorrelationRecord
from app.models.risk import SecurityAlert, RiskAssessment
from app.ai.security.sanitization import sanitize_evidence_dict


class EvidenceService:
    """Collects and sanitizes ground-truth evidence for AI analysis."""

    @staticmethod
    def collect_investigation_evidence(
        db: Session,
        investigation_id: str,
    ) -> Tuple[Dict[str, Any], Set[str]]:
        """Gather evidence for an exfiltration investigation and collect all valid record IDs."""
        available_ids: Set[str] = set()

        inv = (
            db.query(ExfiltrationInvestigation)
            .filter(ExfiltrationInvestigation.id == investigation_id.strip())
            .first()
        )
        if not inv:
            return {}, available_ids

        available_ids.add(inv.id)

        # Evidence links
        links = (
            db.query(InvestigationEvidenceLink)
            .filter(InvestigationEvidenceLink.investigation_id == inv.id)
            .all()
        )
        evidence_links_data = []
        for l in links:
            available_ids.add(l.evidence_id)
            available_ids.add(l.id)
            evidence_links_data.append({
                "evidence_id": l.evidence_id,
                "evidence_type": l.evidence_type,
                "evidence_provenance": l.evidence_provenance,
                "relationship_nature": l.relationship_nature,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "description": l.description,
            })

        # Correlation rules
        rules = (
            db.query(CorrelationRecord)
            .filter(CorrelationRecord.investigation_id == inv.id)
            .all()
        )
        rules_data = []
        for r in rules:
            available_ids.add(r.id)
            rules_data.append({
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "score_contribution": r.score_contribution,
                "relationship_type": r.relationship_type,
                "evidence_completeness": r.evidence_completeness,
                "summary": r.summary,
            })

        context = {
            "investigation_id": inv.id,
            "title": inv.title,
            "description": inv.description,
            "status": inv.status,
            "risk_score": inv.risk_score,
            "severity": inv.severity,
            "evidence_confidence": inv.evidence_confidence,
            "evidence_completeness": inv.evidence_completeness,
            "correlation_window_minutes": inv.correlation_window_minutes,
            "rules_triggered": rules_data,
            "evidence_links": evidence_links_data,
            "available_record_ids": list(available_ids),
        }

        return sanitize_evidence_dict(context), available_ids

    @staticmethod
    def collect_alert_evidence(
        db: Session,
        alert_id: str,
    ) -> Tuple[Dict[str, Any], Set[str]]:
        """Gather evidence for a security alert."""
        available_ids: Set[str] = set()

        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id.strip()).first()
        if not alert:
            return {}, available_ids

        available_ids.add(alert.id)
        if alert.assessment_id:
            available_ids.add(alert.assessment_id)

        assessment_data = None
        if alert.assessment_id:
            assessment = db.query(RiskAssessment).filter(RiskAssessment.id == alert.assessment_id).first()
            if assessment:
                assessment_data = {
                    "assessment_id": assessment.id,
                    "risk_score": assessment.risk_score,
                    "severity": assessment.severity,
                    "explanation": assessment.explanation,
                    "detection_confidence": assessment.detection_confidence,
                }
                if assessment.event_id:
                    available_ids.add(assessment.event_id)

        context = {
            "alert_id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "assessment": assessment_data,
            "available_record_ids": list(available_ids),
        }

        return sanitize_evidence_dict(context), available_ids
