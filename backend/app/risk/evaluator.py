"""Rule Evaluator and Temporal Context Builder for SentinelDLP (Phase 5).

Constructs bounded temporal context (1m, 5m, 15m windows) using indexed
PostgreSQL database queries and evaluates registered security detection rules.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session
from app.models.monitoring import FileActivityEvent, MonitoringSession
from app.risk.rules import get_default_rules
from app.risk.rules.base import BaseDetectionRule, RuleEvaluationResult, TemporalContext


class RuleEvaluator:
    """Coordinates temporal context assembly and rule execution."""

    def __init__(self, rules: Optional[List[BaseDetectionRule]] = None) -> None:
        self.rules = rules or get_default_rules()

    def build_temporal_context(
        self,
        event: FileActivityEvent,
        db: Session,
    ) -> TemporalContext:
        """Query bounded temporal metrics relative to the event's occurred_at timestamp."""
        eval_time = event.occurred_at or datetime.now(timezone.utc)
        t_5m = eval_time - timedelta(minutes=5)
        t_15m = eval_time - timedelta(minutes=15)

        # 1. 5-minute window: distinct modified files
        mod_query = (
            db.query(FileActivityEvent.relative_path)
            .filter(
                FileActivityEvent.root_id == event.root_id,
                FileActivityEvent.event_type == "FILE_MODIFIED",
                FileActivityEvent.is_directory == False,
                FileActivityEvent.occurred_at >= t_5m,
                FileActivityEvent.occurred_at <= eval_time,
            )
            .distinct()
            .limit(50)
            .all()
        )
        mod_paths = [r[0] for r in mod_query]

        # 2. 5-minute window: distinct renamed / moved files
        rename_query = (
            db.query(FileActivityEvent.relative_path)
            .filter(
                FileActivityEvent.root_id == event.root_id,
                FileActivityEvent.event_type.in_(("FILE_RENAMED", "FILE_MOVED")),
                FileActivityEvent.is_directory == False,
                FileActivityEvent.occurred_at >= t_5m,
                FileActivityEvent.occurred_at <= eval_time,
            )
            .distinct()
            .limit(50)
            .all()
        )
        rename_paths = [r[0] for r in rename_query]

        # 3. 5-minute window: repeated changes on this specific file
        changes_this_file = (
            db.query(func.count(FileActivityEvent.id))
            .filter(
                FileActivityEvent.root_id == event.root_id,
                FileActivityEvent.relative_path == event.relative_path,
                FileActivityEvent.occurred_at >= t_5m,
                FileActivityEvent.occurred_at <= eval_time,
            )
            .scalar()
            or 0
        )

        # 4. 15-minute window: sensitive deletions
        del_query = (
            db.query(FileActivityEvent.relative_path)
            .filter(
                FileActivityEvent.root_id == event.root_id,
                FileActivityEvent.event_type == "FILE_DELETED",
                FileActivityEvent.sensitivity_label.in_(("CONFIDENTIAL", "RESTRICTED")),
                FileActivityEvent.occurred_at >= t_15m,
                FileActivityEvent.occurred_at <= eval_time,
            )
            .distinct()
            .limit(50)
            .all()
        )
        del_paths = [r[0] for r in del_query]

        # 5. 15-minute window: total sensitive file events
        sensitive_events_15m = (
            db.query(func.count(FileActivityEvent.id))
            .filter(
                FileActivityEvent.root_id == event.root_id,
                FileActivityEvent.sensitivity_label.in_(("CONFIDENTIAL", "RESTRICTED")),
                FileActivityEvent.occurred_at >= t_15m,
                FileActivityEvent.occurred_at <= eval_time,
            )
            .scalar()
            or 0
        )

        # 6. Session queue overflow telemetry
        session_overflows = 0
        latest_session = (
            db.query(MonitoringSession)
            .filter(MonitoringSession.root_id == event.root_id)
            .order_by(MonitoringSession.started_at.desc())
            .first()
        )
        if latest_session:
            session_overflows = latest_session.queue_overflow_count

        return TemporalContext(
            evaluation_time=eval_time,
            distinct_modified_files_5m=len(mod_paths),
            recent_modified_paths_5m=mod_paths,
            distinct_renamed_files_5m=len(rename_paths),
            recent_renamed_paths_5m=rename_paths,
            changes_for_this_file_5m=changes_this_file,
            sensitive_deletions_15m=len(del_paths),
            recent_deleted_sensitive_paths_15m=del_paths,
            sensitive_events_count_15m=sensitive_events_15m,
            queue_overflow_count=session_overflows,
        )

    def evaluate_rules(
        self,
        event: FileActivityEvent,
        context: TemporalContext,
        policy: dict,
    ) -> List[RuleEvaluationResult]:
        """Run all registered rules against event and context, returning triggers."""
        matches: List[RuleEvaluationResult] = []
        for rule in self.rules:
            try:
                res = rule.evaluate(event, context, policy)
                if res is not None:
                    matches.append(res)
            except Exception:
                # Defensive isolation: a failing rule does not crash the evaluation pipeline
                pass
        return matches
