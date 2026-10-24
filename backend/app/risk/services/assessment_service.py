"""Assessment and Alert Query Service for SentinelDLP (Phase 5).

Provides server-side pagination, structured filtering, and metrics aggregation.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from app.models.risk import AlertAuditLog, RiskAssessment, RuleMatch, SecurityAlert
from app.risk.schemas import (
    AlertAuditLogItem,
    AlertStatisticsResponse,
    PaginatedRiskAssessmentsResponse,
    PaginatedSecurityAlertsResponse,
    RiskAssessmentItem,
    RiskStatisticsResponse,
    RuleMatchItem,
    SecurityAlertDetail,
    SecurityAlertItem,
)
from app.risk.severity import AlertStatus, DetectionConfidence, EvidenceCompleteness, RiskSeverity


class AssessmentService:
    """Provides analytical and operational query services for assessments and alerts."""

    def list_assessments(
        self,
        db: Session,
        root_id: Optional[str] = None,
        severity: Optional[str] = None,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> PaginatedRiskAssessmentsResponse:
        """Query paginated risk assessments with multi-parameter filtering."""
        query = db.query(RiskAssessment)

        if root_id:
            query = query.filter(RiskAssessment.root_id == root_id)
        if severity:
            query = query.filter(RiskAssessment.severity == severity.upper())
        if min_score is not None:
            query = query.filter(RiskAssessment.risk_score >= min_score)
        if max_score is not None:
            query = query.filter(RiskAssessment.risk_score <= max_score)
        if status:
            query = query.filter(RiskAssessment.assessment_status == status)

        total = query.count()
        offset = (page - 1) * page_size
        records = query.order_by(desc(RiskAssessment.assessed_at)).offset(offset).limit(page_size).all()

        items: List[RiskAssessmentItem] = []
        for r in records:
            rule_items = [
                RuleMatchItem(
                    id=m.id,
                    rule_id=m.rule_id,
                    rule_name=m.rule_name,
                    rule_version=m.rule_version,
                    score_contribution=m.score_contribution,
                    severity_impact=RiskSeverity(m.severity_impact),
                    match_timestamp=m.match_timestamp,
                    evidence_data=json.loads(m.evidence_data) if m.evidence_data else {},
                )
                for m in r.rule_matches
            ]
            items.append(
                RiskAssessmentItem(
                    id=r.id,
                    event_id=r.event_id,
                    root_id=r.root_id,
                    associated_file_id=r.associated_file_id,
                    risk_score=r.risk_score,
                    severity=RiskSeverity(r.severity),
                    evidence_completeness=EvidenceCompleteness(r.evidence_completeness),
                    detection_confidence=DetectionConfidence(r.detection_confidence),
                    scoring_policy_version=r.scoring_policy_version,
                    assessment_status=r.assessment_status,
                    explanation=r.explanation,
                    limitations=r.limitations,
                    recommended_action=r.recommended_action,
                    assessed_at=r.assessed_at,
                    rule_matches=rule_items,
                    alert_id=r.alert.id if r.alert else None,
                )
            )

        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return PaginatedRiskAssessmentsResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_assessment_by_id(
        self,
        assessment_id: str,
        db: Session,
    ) -> Optional[RiskAssessmentItem]:
        """Retrieve complete assessment record with rule matches and linked alert."""
        r = db.query(RiskAssessment).filter(RiskAssessment.id == assessment_id).first()
        if not r:
            return None

        rule_items = [
            RuleMatchItem(
                id=m.id,
                rule_id=m.rule_id,
                rule_name=m.rule_name,
                rule_version=m.rule_version,
                score_contribution=m.score_contribution,
                severity_impact=RiskSeverity(m.severity_impact),
                match_timestamp=m.match_timestamp,
                evidence_data=json.loads(m.evidence_data) if m.evidence_data else {},
            )
            for m in r.rule_matches
        ]
        return RiskAssessmentItem(
            id=r.id,
            event_id=r.event_id,
            root_id=r.root_id,
            associated_file_id=r.associated_file_id,
            risk_score=r.risk_score,
            severity=RiskSeverity(r.severity),
            evidence_completeness=EvidenceCompleteness(r.evidence_completeness),
            detection_confidence=DetectionConfidence(r.detection_confidence),
            scoring_policy_version=r.scoring_policy_version,
            assessment_status=r.assessment_status,
            explanation=r.explanation,
            limitations=r.limitations,
            recommended_action=r.recommended_action,
            assessed_at=r.assessed_at,
            rule_matches=rule_items,
            alert_id=r.alert.id if r.alert else None,
        )

    def get_risk_statistics(self, db: Session) -> RiskStatisticsResponse:
        """Calculate aggregated risk distribution metrics."""
        total = db.query(func.count(RiskAssessment.id)).scalar() or 0
        low = db.query(func.count(RiskAssessment.id)).filter(RiskAssessment.severity == "LOW").scalar() or 0
        med = db.query(func.count(RiskAssessment.id)).filter(RiskAssessment.severity == "MEDIUM").scalar() or 0
        high = db.query(func.count(RiskAssessment.id)).filter(RiskAssessment.severity == "HIGH").scalar() or 0
        crit = db.query(func.count(RiskAssessment.id)).filter(RiskAssessment.severity == "CRITICAL").scalar() or 0

        avg_score = db.query(func.avg(RiskAssessment.risk_score)).scalar() or 0.0

        return RiskStatisticsResponse(
            total_assessments=total,
            low_count=low,
            medium_count=med,
            high_count=high,
            critical_count=crit,
            average_score=round(float(avg_score), 2),
            score_distribution={
                "0-29": low,
                "30-59": med,
                "60-79": high,
                "80-100": crit,
            },
        )

    def list_alerts(
        self,
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        root_id: Optional[str] = None,
        min_score: Optional[int] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> PaginatedSecurityAlertsResponse:
        """Query paginated security alerts with operational filters."""
        query = db.query(SecurityAlert)

        if status:
            query = query.filter(SecurityAlert.status == status.upper())
        if severity:
            query = query.filter(SecurityAlert.severity == severity.upper())
        if root_id:
            query = query.filter(SecurityAlert.root_id == root_id)
        if min_score is not None:
            query = query.filter(SecurityAlert.risk_score >= min_score)

        total = query.count()
        offset = (page - 1) * page_size
        records = query.order_by(desc(SecurityAlert.created_at)).offset(offset).limit(page_size).all()

        items = [
            SecurityAlertItem(
                id=a.id,
                assessment_id=a.assessment_id,
                root_id=a.root_id,
                title=a.title,
                description=a.description,
                severity=RiskSeverity(a.severity),
                risk_score=a.risk_score,
                status=AlertStatus(a.status),
                deduplication_key=a.deduplication_key,
                repeat_count=a.repeat_count,
                recommended_action=a.recommended_action,
                created_at=a.created_at,
                updated_at=a.updated_at,
                acknowledged_at=a.acknowledged_at,
                resolved_at=a.resolved_at,
                resolution_notes=a.resolution_notes,
            )
            for a in records
        ]

        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return PaginatedSecurityAlertsResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_alert_by_id(
        self,
        alert_id: str,
        db: Session,
    ) -> Optional[SecurityAlertDetail]:
        """Retrieve comprehensive alert detail with linked assessment and full audit trail."""
        a = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not a:
            return None

        assessment_item = None
        if a.assessment:
            rule_items = [
                RuleMatchItem(
                    id=m.id,
                    rule_id=m.rule_id,
                    rule_name=m.rule_name,
                    rule_version=m.rule_version,
                    score_contribution=m.score_contribution,
                    severity_impact=RiskSeverity(m.severity_impact),
                    match_timestamp=m.match_timestamp,
                    evidence_data=json.loads(m.evidence_data) if m.evidence_data else {},
                )
                for m in a.assessment.rule_matches
            ]
            assessment_item = RiskAssessmentItem(
                id=a.assessment.id,
                event_id=a.assessment.event_id,
                root_id=a.assessment.root_id,
                associated_file_id=a.assessment.associated_file_id,
                risk_score=a.assessment.risk_score,
                severity=RiskSeverity(a.assessment.severity),
                evidence_completeness=EvidenceCompleteness(a.assessment.evidence_completeness),
                detection_confidence=DetectionConfidence(a.assessment.detection_confidence),
                scoring_policy_version=a.assessment.scoring_policy_version,
                assessment_status=a.assessment.assessment_status,
                explanation=a.assessment.explanation,
                limitations=a.assessment.limitations,
                recommended_action=a.assessment.recommended_action,
                assessed_at=a.assessment.assessed_at,
                rule_matches=rule_items,
                alert_id=a.id,
            )

        audit_items = [
            AlertAuditLogItem(
                id=log.id,
                alert_id=log.alert_id,
                previous_status=log.previous_status,
                new_status=log.new_status,
                action=log.action,
                analyst_notes=log.analyst_notes,
                performed_by=log.performed_by,
                performed_at=log.performed_at,
            )
            for log in a.audit_logs
        ]

        return SecurityAlertDetail(
            id=a.id,
            assessment_id=a.assessment_id,
            root_id=a.root_id,
            title=a.title,
            description=a.description,
            severity=RiskSeverity(a.severity),
            risk_score=a.risk_score,
            status=AlertStatus(a.status),
            deduplication_key=a.deduplication_key,
            repeat_count=a.repeat_count,
            recommended_action=a.recommended_action,
            created_at=a.created_at,
            updated_at=a.updated_at,
            acknowledged_at=a.acknowledged_at,
            resolved_at=a.resolved_at,
            resolution_notes=a.resolution_notes,
            assessment=assessment_item,
            audit_logs=audit_items,
        )

    def get_alert_statistics(self, db: Session) -> AlertStatisticsResponse:
        """Calculate aggregated alert lifecycle triage metrics."""
        total = db.query(func.count(SecurityAlert.id)).scalar() or 0
        open_c = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "OPEN").scalar() or 0
        ack_c = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "ACKNOWLEDGED").scalar() or 0
        inv_c = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "INVESTIGATING").scalar() or 0
        res_c = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "RESOLVED").scalar() or 0
        fp_c = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.status == "FALSE_POSITIVE").scalar() or 0

        low = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "LOW").scalar() or 0
        med = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "MEDIUM").scalar() or 0
        high = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "HIGH").scalar() or 0
        crit = db.query(func.count(SecurityAlert.id)).filter(SecurityAlert.severity == "CRITICAL").scalar() or 0

        return AlertStatisticsResponse(
            total_alerts=total,
            open_count=open_c,
            acknowledged_count=ack_c,
            investigating_count=inv_c,
            resolved_count=res_c,
            false_positive_count=fp_c,
            by_severity={
                "LOW": low,
                "MEDIUM": med,
                "HIGH": high,
                "CRITICAL": crit,
            },
        )


assessment_service = AssessmentService()
