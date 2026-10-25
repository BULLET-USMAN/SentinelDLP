"""Bounded Temporal Exfiltration Correlation Engine (Phase 6).

Coordinates the evaluation of file telemetry, archive events, and outbound transfer records
across configurable temporal windows (1m, 5m, 15m, 30m, 60m).
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from app.exfiltration.policies import is_archive_file
from app.exfiltration.rules import get_all_exfiltration_rules
from app.exfiltration.rules.base import ExfiltrationContext, ExfiltrationRuleMatch
from app.exfiltration.services.investigation_service import InvestigationService
from app.models.exfiltration import ExfiltrationInvestigation, TransferEvent
from app.models.monitoring import FileActivityEvent
from app.models.risk import RiskAssessment


class ExfiltrationCorrelator:
    """Evaluates multi-source telemetry within bounded windows to identify exfiltration patterns."""

    def __init__(self, db: Session):
        self.db = db
        self.rules = get_all_exfiltration_rules()

    def run_correlation(
        self,
        window_minutes: int = 15,
        endpoint_id: Optional[str] = "endpoint-alpha-01",
    ) -> List[ExfiltrationInvestigation]:
        """Execute correlation rules across telemetry occurring within the window."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=window_minutes)

        # 1. Fetch file activity events
        file_query = self.db.query(FileActivityEvent).filter(
            FileActivityEvent.occurred_at >= start_time,
            FileActivityEvent.occurred_at <= end_time,
        )
        file_events = file_query.order_by(FileActivityEvent.occurred_at.asc()).all()

        # 2. Fetch outbound transfer events
        transfer_query = self.db.query(TransferEvent).filter(
            TransferEvent.occurred_at >= start_time,
            TransferEvent.occurred_at <= end_time,
            TransferEvent.direction == "OUTBOUND",
        )
        if endpoint_id:
            transfer_query = transfer_query.filter(TransferEvent.source_endpoint_id == endpoint_id)
        transfer_events = transfer_query.order_by(TransferEvent.occurred_at.asc()).all()

        # 3. Fetch risk assessments
        risk_assessments = (
            self.db.query(RiskAssessment)
            .filter(
                RiskAssessment.assessed_at >= start_time,
                RiskAssessment.assessed_at <= end_time,
            )
            .all()
        )

        # 4. Categorize archive vs sensitive events
        archive_events = [e for e in file_events if is_archive_file(e.file_path)]
        sensitive_file_events = [
            e for e in file_events
            if (e.sensitivity_label and e.sensitivity_label.upper() in ("CONFIDENTIAL", "RESTRICTED", "INTERNAL"))
            or any(kw in e.file_path.lower() for kw in ("confidential", "secret", "password", "salary", "classified", "key", "token"))
        ]

        # 5. Build context
        context = ExfiltrationContext(
            start_time=start_time,
            end_time=end_time,
            window_minutes=window_minutes,
            endpoint_id=endpoint_id,
            file_events=file_events,
            transfer_events=transfer_events,
            risk_assessments=risk_assessments,
            archive_events=archive_events,
            sensitive_file_events=sensitive_file_events,
        )

        # 6. Evaluate all rules
        matches: List[ExfiltrationRuleMatch] = []
        for rule in self.rules:
            result = rule.evaluate(context)
            if result:
                matches.append(result)

        if not matches:
            return []

        # 7. Create Investigation record
        investigation = InvestigationService.create_investigation_from_matches(
            db=self.db,
            matches=matches,
            window_minutes=window_minutes,
            endpoint_id=endpoint_id,
        )

        return [investigation]
