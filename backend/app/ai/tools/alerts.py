"""Read-only alert and risk assessment investigation tools."""

from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.risk import SecurityAlert, RiskAssessment, RuleMatch
from app.ai.security.sanitization import sanitize_evidence_dict


def get_alert(db: Session, alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve structured security alert metadata and associated risk score."""
    if not alert_id:
        return None

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id.strip()).first()
    if not alert:
        return None

    data = {
        "alert_id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "deduplication_key": alert.deduplication_key,
        "repeat_count": alert.repeat_count,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "assessment_id": alert.assessment_id,
        "root_id": alert.root_id,
    }
    return sanitize_evidence_dict(data)


def get_risk_assessment(db: Session, assessment_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve detailed threat risk assessment breakdown including rule match scores."""
    if not assessment_id:
        return None

    assessment = db.query(RiskAssessment).filter(RiskAssessment.id == assessment_id.strip()).first()
    if not assessment:
        return None

    rule_matches = db.query(RuleMatch).filter(RuleMatch.assessment_id == assessment.id).all()
    matches_data = [
        {
            "rule_id": rm.rule_id,
            "rule_name": rm.rule_name,
            "score_contribution": rm.score_contribution,
            "severity_impact": rm.severity_impact,
        }
        for rm in rule_matches
    ]

    data = {
        "assessment_id": assessment.id,
        "risk_score": assessment.risk_score,
        "severity": assessment.severity,
        "explanation": assessment.explanation,
        "evidence_completeness": assessment.evidence_completeness,
        "detection_confidence": assessment.detection_confidence,
        "scoring_policy_version": assessment.scoring_policy_version,
        "recommended_action": assessment.recommended_action,
        "assessed_at": assessment.assessed_at.isoformat() if assessment.assessed_at else None,
        "rule_matches": matches_data,
        "event_id": assessment.event_id,
    }
    return sanitize_evidence_dict(data)
