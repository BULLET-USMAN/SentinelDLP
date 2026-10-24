"""Security Alert Generation, Deduplication, and Lifecycle Service (Phase 5).

Handles SOC alert creation, sliding-window suppression, repeat-count tracking,
and analyst triage state transitions with an immutable audit log.
"""

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Optional
import uuid
from sqlalchemy.orm import Session
from app.models.risk import AlertAuditLog, RiskAssessment, SecurityAlert
from app.risk.policies import DEFAULT_SCORING_POLICY
from app.risk.severity import AlertStatus, RiskSeverity, VALID_STATUS_TRANSITIONS


class AlertService:
    """Manages creation, deduplication, suppression, and lifecycle triage of alerts."""

    @staticmethod
    def generate_deduplication_key(
        assessment: RiskAssessment,
        primary_rule_id: str,
        db: Optional[Session] = None,
    ) -> str:
        """Create a deterministic deduplication hash to cluster repetitive alert activity."""
        file_token = assessment.associated_file_id
        if not file_token and assessment.event:
            file_token = assessment.event.relative_path
        if not file_token and db:
            from app.models.monitoring import FileActivityEvent
            ev = db.query(FileActivityEvent).filter(FileActivityEvent.id == assessment.event_id).first()
            if ev:
                file_token = ev.relative_path

        if not file_token:
            file_token = assessment.event_id

        raw_key = f"{assessment.root_id}:{primary_rule_id}:{file_token}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]

    def process_alert_for_assessment(
        self,
        assessment: RiskAssessment,
        primary_rule_id: str,
        db: Session,
        policy: Optional[dict] = None,
    ) -> Optional[SecurityAlert]:
        """Evaluate alerting policy and create or suppress a SecurityAlert."""
        active_policy = policy or DEFAULT_SCORING_POLICY
        alert_cfg = active_policy.get("alerting", {})
        min_score = alert_cfg.get("min_alert_score", 30)
        auto_rules = set(alert_cfg.get("auto_alert_rules", []))
        suppression_window = alert_cfg.get("suppression_window_seconds", 300)

        # 1. Check if eligible for alert
        is_eligible = (
            assessment.risk_score >= min_score
            or primary_rule_id in auto_rules
            or assessment.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
        )
        if not is_eligible:
            return None

        now = datetime.now(timezone.utc)
        dedup_key = self.generate_deduplication_key(assessment, primary_rule_id, db)
        window_start = now - timedelta(seconds=suppression_window)

        # 2. Check for an active existing alert with this deduplication key
        existing_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.deduplication_key == dedup_key,
                SecurityAlert.status.in_((AlertStatus.OPEN.value, AlertStatus.INVESTIGATING.value, AlertStatus.ACKNOWLEDGED.value)),
                SecurityAlert.updated_at >= window_start,
            )
            .order_by(SecurityAlert.created_at.desc())
            .first()
        )

        if existing_alert:
            # Deduplicate and suppress: increment repeat counter
            existing_alert.repeat_count += 1
            existing_alert.updated_at = now
            # If incoming assessment is higher severity/score, escalate existing alert
            if assessment.risk_score > existing_alert.risk_score:
                existing_alert.risk_score = assessment.risk_score
                existing_alert.severity = assessment.severity

            # Record suppression audit entry
            audit = AlertAuditLog(
                id=str(uuid.uuid4()),
                alert_id=existing_alert.id,
                previous_status=existing_alert.status,
                new_status=existing_alert.status,
                action="suppressed_duplicate",
                analyst_notes=f"Suppressed duplicate alert within {suppression_window}s window (occurrence #{existing_alert.repeat_count})",
                performed_by="system_deduplicator",
                performed_at=now,
            )
            db.add(audit)
            db.flush()
            return existing_alert

        # 3. Create fresh SecurityAlert
        title = f"{assessment.severity} Risk: {primary_rule_id or 'Elevated Activity'}"
        alert_record = SecurityAlert(
            id=str(uuid.uuid4()),
            assessment_id=assessment.id,
            root_id=assessment.root_id,
            title=title,
            description=assessment.explanation,
            severity=assessment.severity,
            risk_score=assessment.risk_score,
            status=AlertStatus.OPEN.value,
            deduplication_key=dedup_key,
            repeat_count=1,
            suppression_window_seconds=suppression_window,
            recommended_action=assessment.recommended_action,
            created_at=now,
            updated_at=now,
        )
        db.add(alert_record)
        db.flush()

        # Record creation audit log
        audit = AlertAuditLog(
            id=str(uuid.uuid4()),
            alert_id=alert_record.id,
            previous_status="NONE",
            new_status=AlertStatus.OPEN.value,
            action="alert_created",
            analyst_notes=f"Alert generated from assessment '{assessment.id}' (Score: {assessment.risk_score})",
            performed_by="sentinel_risk_engine",
            performed_at=now,
        )
        db.add(audit)
        db.flush()

        return alert_record

    def update_alert_status(
        self,
        alert_id: str,
        new_status: AlertStatus,
        analyst_notes: Optional[str],
        performed_by: str,
        db: Session,
    ) -> SecurityAlert:
        """Execute a validated analyst triage status transition with audit logging."""
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise ValueError(f"Security alert with ID '{alert_id}' not found.")

        current_enum = AlertStatus(alert.status)
        allowed_targets = VALID_STATUS_TRANSITIONS.get(current_enum, set())
        if new_status not in allowed_targets:
            raise ValueError(
                f"Invalid status transition from '{alert.status}' to '{new_status.value}'."
            )

        now = datetime.now(timezone.utc)
        prev_status = alert.status
        alert.status = new_status.value
        alert.updated_at = now

        if new_status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = now
        elif new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = now
            if analyst_notes:
                alert.resolution_notes = analyst_notes

        action_name = f"status_changed_to_{new_status.value.lower()}"
        audit = AlertAuditLog(
            id=str(uuid.uuid4()),
            alert_id=alert.id,
            previous_status=prev_status,
            new_status=new_status.value,
            action=action_name,
            analyst_notes=analyst_notes,
            performed_by=performed_by or "security_analyst",
            performed_at=now,
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)
        return alert


alert_service = AlertService()
