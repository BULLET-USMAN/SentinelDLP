"""Central Risk Scoring Engine for SentinelDLP (Phase 5).

Coordinates rule evaluation, evidence quality calculation, deterministic threat scoring,
persistence, and SOC alert lifecycle generation.
"""

from datetime import datetime, timezone
import json
from typing import Optional
import uuid
from sqlalchemy.orm import Session
from app.core.logging import logger
from app.models.monitoring import FileActivityEvent
from app.models.risk import RiskAssessment, RuleMatch, SecurityAlert
from app.risk.evaluator import RuleEvaluator
from app.risk.evidence import evaluate_evidence_quality, sanitize_evidence_data
from app.risk.policies import DEFAULT_SCORING_POLICY, POLICY_VERSION
from app.risk.scoring import calculate_risk_score
from app.risk.services.alert_service import alert_service


class RiskEngine:
    """Singleton engine orchestrating security threat risk scoring and alert dispatch."""

    def __init__(self) -> None:
        self.evaluator = RuleEvaluator()
        self.policy = DEFAULT_SCORING_POLICY

    def evaluate_event(
        self,
        event: FileActivityEvent,
        db: Session,
        policy_override: Optional[dict] = None,
    ) -> RiskAssessment:
        """Evaluate a normalized security activity event, persist assessment, and trigger alerts.

        Guarantees idempotency: if an assessment already exists for this event_id, returns it.
        """
        # 1. Idempotency safeguard
        existing = (
            db.query(RiskAssessment)
            .filter(RiskAssessment.event_id == event.id)
            .first()
        )
        if existing:
            return existing

        active_policy = policy_override or self.policy

        # 2. Build temporal context from bounded database queries
        context = self.evaluator.build_temporal_context(event, db)

        # 3. Evaluate detection rules
        matches = self.evaluator.evaluate_rules(event, context, active_policy)

        # 4. Determine evidence completeness and confidence
        has_coverage_warn = any(m.is_coverage_warning for m in matches)
        completeness, confidence = evaluate_evidence_quality(
            event=event,
            is_coverage_warning=has_coverage_warn,
        )

        # 5. Calculate deterministic normalized score
        score_data = calculate_risk_score(event, matches)

        # 6. Persist RiskAssessment
        assessment_id = str(uuid.uuid4())
        assessment = RiskAssessment(
            id=assessment_id,
            event_id=event.id,
            root_id=event.root_id,
            associated_file_id=event.associated_file_id,
            risk_score=score_data.risk_score,
            severity=score_data.severity.value,
            evidence_completeness=completeness.value,
            detection_confidence=confidence.value,
            scoring_policy_version=active_policy.get("policy_version", POLICY_VERSION),
            assessment_status=score_data.assessment_status,
            explanation=score_data.explanation,
            limitations=score_data.limitations,
            recommended_action=score_data.recommended_action,
            assessed_at=datetime.now(timezone.utc),
        )
        db.add(assessment)
        db.flush()

        # 7. Persist individual RuleMatch records
        primary_rule_id = ""
        highest_points = -1
        for match in matches:
            if match.score_contribution > highest_points:
                highest_points = match.score_contribution
                primary_rule_id = match.rule_id

            clean_evidence = sanitize_evidence_data(match.evidence)
            match_record = RuleMatch(
                id=str(uuid.uuid4()),
                assessment_id=assessment_id,
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                rule_version=match.rule_version,
                score_contribution=match.score_contribution,
                severity_impact=match.severity_impact.value,
                match_timestamp=datetime.now(timezone.utc),
                evidence_data=json.dumps(clean_evidence),
            )
            db.add(match_record)

        db.flush()

        # 8. Evaluate alert generation policy
        if primary_rule_id or score_data.risk_score > 0:
            alert_service.process_alert_for_assessment(
                assessment=assessment,
                primary_rule_id=primary_rule_id or "ELEVATED_ACTIVITY",
                db=db,
                policy=active_policy,
            )

        logger.info(
            f"Evaluated RiskAssessment for event {event.id}: score={score_data.risk_score} "
            f"({score_data.severity.value}), rules_matched={len(matches)}"
        )
        return assessment


risk_engine = RiskEngine()
