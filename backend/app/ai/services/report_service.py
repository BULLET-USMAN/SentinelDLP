"""Report persistence, retrieval, and analyst review service."""

import json
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.ai import AIInvestigationReport
from app.ai.schemas import AIInvestigationReportResponse, ObservedFactItem, MitreAttackMappingItem


class ReportService:
    """Handles storage, retrieval, and analyst validation of AI investigation reports."""

    @staticmethod
    def to_schema(report: AIInvestigationReport) -> AIInvestigationReportResponse:
        """Convert SQLAlchemy report entity into Pydantic response schema."""
        try:
            facts_raw = json.loads(report.observed_facts_json or "[]")
            facts = [ObservedFactItem(**f) if isinstance(f, dict) else ObservedFactItem(fact=str(f)) for f in facts_raw]
        except Exception:
            facts = []

        try:
            mitre_raw = json.loads(report.mitre_attack_mappings_json or "[]")
            mitre = [MitreAttackMappingItem(**m) for m in mitre_raw]
        except Exception:
            mitre = []

        try:
            explanations = json.loads(report.possible_explanations_json or "[]")
        except Exception:
            explanations = []

        try:
            missing = json.loads(report.missing_evidence_json or "[]")
        except Exception:
            missing = []

        try:
            actions = json.loads(report.recommended_actions_json or "[]")
        except Exception:
            actions = []

        try:
            references = json.loads(report.evidence_references_json or "[]")
        except Exception:
            references = []

        return AIInvestigationReportResponse(
            id=report.id,
            investigation_id=report.investigation_id,
            alert_id=report.alert_id,
            model_id=report.model_id,
            provider_type=report.provider_type,
            status=report.status,
            executive_summary=report.executive_summary,
            assessment=report.assessment,
            confidence_assessment=report.confidence_assessment,
            evidence_completeness=report.evidence_completeness,
            observed_facts=facts,
            possible_explanations=explanations,
            missing_evidence=missing,
            recommended_actions=actions,
            mitre_attack_mappings=mitre,
            evidence_references=references,
            tool_calls_count=report.tool_calls_count,
            prompt_template_version=report.prompt_template_version,
            report_schema_version=report.report_schema_version,
            analyst_review_status=report.analyst_review_status,
            analyst_feedback_notes=report.analyst_feedback_notes,
            reviewed_by=report.reviewed_by,
            reviewed_at=report.reviewed_at,
            created_at=report.created_at,
            execution_duration_ms=report.execution_duration_ms,
        )

    @classmethod
    def get_report_by_id(cls, db: Session, report_id: str) -> Optional[AIInvestigationReportResponse]:
        """Fetch a specific report by report_id."""
        report = db.query(AIInvestigationReport).filter(AIInvestigationReport.id == report_id.strip()).first()
        if not report:
            return None
        return cls.to_schema(report)

    @classmethod
    def list_reports_for_investigation(
        cls, db: Session, investigation_id: str
    ) -> List[AIInvestigationReportResponse]:
        """Retrieve all historical AI reports generated for an investigation."""
        reports = (
            db.query(AIInvestigationReport)
            .filter(AIInvestigationReport.investigation_id == investigation_id.strip())
            .order_by(AIInvestigationReport.created_at.desc())
            .all()
        )
        return [cls.to_schema(r) for r in reports]

    @classmethod
    def record_feedback(
        cls,
        db: Session,
        report_id: str,
        status: str,
        notes: Optional[str] = None,
        analyst_name: str = "soc_analyst",
    ) -> Optional[AIInvestigationReportResponse]:
        """Record analyst validation status and feedback on an AI report."""
        report = db.query(AIInvestigationReport).filter(AIInvestigationReport.id == report_id.strip()).first()
        if not report:
            return None

        report.analyst_review_status = status
        report.analyst_feedback_notes = notes
        report.reviewed_by = analyst_name
        report.reviewed_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(report)
        return cls.to_schema(report)
