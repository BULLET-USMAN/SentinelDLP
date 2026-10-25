"""Orchestration engine for AI SOC Analyst investigation workflows."""

import json
import time
from typing import Optional
from sqlalchemy.orm import Session

from app.models.ai import AIInvestigationReport
from app.ai.client import get_ai_provider
from app.ai.services.evidence_service import EvidenceService
from app.ai.services.report_service import ReportService
from app.ai.security.output_validation import sanitize_and_validate_report
from app.ai.schemas import AIInvestigationReportResponse


class AnalystService:
    """Orchestrates end-to-end AI security investigations and structured report synthesis."""

    @classmethod
    async def analyze_investigation(
        cls,
        db: Session,
        investigation_id: str,
        analyst_query: Optional[str] = None,
        force_refresh: bool = False,
    ) -> AIInvestigationReportResponse:
        start_time = time.time()

        # Check for existing completed report if force_refresh is False
        if not force_refresh:
            existing_reports = ReportService.list_reports_for_investigation(db, investigation_id)
            if existing_reports:
                return existing_reports[0]

        # 1. Collect and sanitize ground-truth evidence
        context, available_record_ids = EvidenceService.collect_investigation_evidence(db, investigation_id)
        if not context:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        if analyst_query:
            context["analyst_inquiry"] = analyst_query

        # 2. Invoke local AI Provider (Mock or Ollama)
        provider = get_ai_provider()
        raw_report = await provider.generate_investigation_report(context)

        # 3. Output Validation & Anti-Hallucination Filtering
        validated_report = sanitize_and_validate_report(raw_report, available_record_ids)

        duration_ms = int((time.time() - start_time) * 1000)

        # 4. Persist structured report to PostgreSQL
        report = AIInvestigationReport(
            investigation_id=investigation_id,
            alert_id=context.get("alert_id"),
            model_id=validated_report.get("model_id", "mock-sentinel-v1"),
            provider_type=validated_report.get("provider_type", "mock"),
            status="COMPLETED",
            executive_summary=validated_report.get("executive_summary", "Security assessment complete."),
            assessment=validated_report.get("assessment", "Assessment based on available evidence."),
            confidence_assessment=validated_report.get("confidence_assessment", "PARTIAL_SUPPORT"),
            evidence_completeness=validated_report.get("evidence_completeness", "PARTIAL"),
            observed_facts_json=json.dumps(validated_report.get("observed_facts", []), default=str),
            possible_explanations_json=json.dumps(validated_report.get("possible_explanations", []), default=str),
            missing_evidence_json=json.dumps(validated_report.get("missing_evidence", []), default=str),
            recommended_actions_json=json.dumps(validated_report.get("recommended_actions", []), default=str),
            mitre_attack_mappings_json=json.dumps(validated_report.get("mitre_attack_mappings", []), default=str),
            evidence_references_json=json.dumps(validated_report.get("evidence_references", []), default=str),
            tool_calls_count=validated_report.get("tool_calls_count", 0),
            prompt_template_version="v1.0",
            report_schema_version="v1.0",
            analyst_review_status="PENDING",
            execution_duration_ms=duration_ms,
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        return ReportService.to_schema(report)
