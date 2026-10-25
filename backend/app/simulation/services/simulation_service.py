"""Simulation Lifecycle Orchestration Service for SentinelDLP (Phase 10)."""

from datetime import datetime, timezone
import json
from typing import List, Optional
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.simulation import SimulationRun, SimulationResult, SimulationReport
from app.simulation.evaluator import EvaluationResult
from app.simulation.scenario_registry import get_scenario
from app.simulation.scenario_runner import ScenarioRunner
from app.simulation.schemas import (
    ScenarioRunRequest,
    SimulationResultResponse,
    SimulationRunResponse,
    SimulationStepLog,
)
from app.simulation.services.reporting_service import ReportingService


class SimulationService:
    """Manages creation, execution, retrieval, and cancellation of simulation runs."""

    @classmethod
    def start_run(cls, db: Session, request: ScenarioRunRequest) -> SimulationRunResponse:
        """Initialize and execute a security test scenario."""
        scenario = get_scenario(request.scenario_id)
        if not scenario:
            raise ValueError(f"Unknown scenario ID: {request.scenario_id}")

        run_id = str(uuid.uuid4())
        started_at = datetime.utcnow()

        # 1. Create initial Run record
        run = SimulationRun(
            id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            status="RUNNING",
            started_at=started_at,
            summary="Simulation scenario is executing...",
            execution_log_json="[]",
            metrics_json="{}",
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        # 2. Execute scenario via ScenarioRunner
        runner = ScenarioRunner(
            db=db,
            scenario=scenario,
            run_id=run_id,
            seed=request.custom_seed or 42,
            auto_cleanup=request.auto_cleanup,
        )
        eval_result = runner.run()

        # 3. Create Result record
        completed_at = datetime.utcnow()
        result = SimulationResult(
            id=str(uuid.uuid4()),
            run_id=run.id,
            pass_status=eval_result.pass_status,
            expected_events_count=eval_result.expected_events_count,
            actual_events_count=eval_result.actual_events_count,
            expected_rules_json=json.dumps(eval_result.expected_rules),
            actual_rules_json=json.dumps(eval_result.actual_rules),
            matched_rules_json=json.dumps(eval_result.matched_rules),
            unmatched_rules_json=json.dumps(eval_result.unmatched_rules),
            unexpected_rules_json=json.dumps(eval_result.unexpected_rules),
            expected_alerts_count=eval_result.expected_alerts_count,
            actual_alerts_count=eval_result.actual_alerts_count,
            expected_investigations_count=eval_result.expected_investigations_count,
            actual_investigations_count=eval_result.actual_investigations_count,
            precision=eval_result.precision,
            recall=eval_result.recall,
            f1_score=eval_result.f1_score,
            false_positive_rate=eval_result.false_positive_rate,
            latency_ms=eval_result.latency_ms,
            failure_reasons_json=json.dumps(eval_result.failure_reasons),
        )
        db.add(result)

        # 4. Update Run record
        run.status = eval_result.pass_status
        run.completed_at = completed_at
        run.duration_ms = int(eval_result.latency_ms)
        run.summary = (
            f"Validation outcome: {eval_result.pass_status} | "
            f"F1 Score: {eval_result.f1_score:.2f} | "
            f"Precision: {eval_result.precision:.2f} | "
            f"Recall: {eval_result.recall:.2f}"
        )
        run.execution_log_json = json.dumps([log.model_dump() for log in runner.logs])
        run.metrics_json = json.dumps(
            {
                "precision": eval_result.precision,
                "recall": eval_result.recall,
                "f1_score": eval_result.f1_score,
                "fpr": eval_result.false_positive_rate,
            }
        )

        # 5. Generate and store markdown report
        report_text = ReportingService.generate_report_content(run=run, result=result)
        report = SimulationReport(
            id=str(uuid.uuid4()),
            run_id=run.id,
            title=f"Validation Report - {scenario.scenario_id}: {scenario.name}",
            markdown_content=report_text,
            execution_metadata_json=json.dumps(
                {
                    "scenario_id": scenario.scenario_id,
                    "seed": request.custom_seed or 42,
                    "latency_ms": eval_result.latency_ms,
                }
            ),
        )
        db.add(report)

        db.commit()
        db.refresh(run)
        db.refresh(result)

        return cls._format_run_response(run, result)

    @classmethod
    def get_run(cls, db: Session, run_id: str) -> Optional[SimulationRunResponse]:
        """Fetch a specific simulation run by ID."""
        run = db.query(SimulationRun).filter(SimulationRun.id == run_id).first()
        if not run:
            return None
        result = db.query(SimulationResult).filter(SimulationResult.run_id == run.id).first()
        return cls._format_run_response(run, result)

    @classmethod
    def list_runs(
        cls,
        db: Session,
        limit: int = 20,
        offset: int = 0,
        scenario_id: Optional[str] = None,
    ) -> List[SimulationRunResponse]:
        """List historical simulation runs."""
        query = db.query(SimulationRun).order_by(desc(SimulationRun.created_at))
        if scenario_id:
            query = query.filter(SimulationRun.scenario_id == scenario_id)
        runs = query.offset(offset).limit(limit).all()

        responses = []
        for r in runs:
            res = db.query(SimulationResult).filter(SimulationResult.run_id == r.id).first()
            responses.append(cls._format_run_response(r, res))
        return responses

    @classmethod
    def cancel_run(cls, db: Session, run_id: str) -> bool:
        """Cancel an in-progress simulation run."""
        run = db.query(SimulationRun).filter(SimulationRun.id == run_id).first()
        if not run:
            return False
        if run.status in ("PENDING", "RUNNING"):
            run.status = "CANCELLED"
            run.completed_at = datetime.utcnow()
            run.summary = "Simulation run was cancelled by user."
            db.commit()
            return True
        return False

    @classmethod
    def get_result_for_run(cls, db: Session, run_id: str) -> Optional[SimulationResultResponse]:
        """Fetch result record for a specific run."""
        res = db.query(SimulationResult).filter(SimulationResult.run_id == run_id).first()
        if not res:
            return None
        return cls._format_result_response(res)

    @staticmethod
    def _format_result_response(res: SimulationResult) -> SimulationResultResponse:
        """Convert a DB SimulationResult model to response schema."""
        return SimulationResultResponse(
            id=res.id,
            run_id=res.run_id,
            pass_status=res.pass_status,
            expected_events_count=res.expected_events_count,
            actual_events_count=res.actual_events_count,
            expected_rules=json.loads(res.expected_rules_json),
            actual_rules=json.loads(res.actual_rules_json),
            matched_rules=json.loads(res.matched_rules_json),
            unmatched_rules=json.loads(res.unmatched_rules_json),
            unexpected_rules=json.loads(res.unexpected_rules_json),
            expected_alerts_count=res.expected_alerts_count,
            actual_alerts_count=res.actual_alerts_count,
            expected_investigations_count=res.expected_investigations_count,
            actual_investigations_count=res.actual_investigations_count,
            precision=res.precision,
            recall=res.recall,
            f1_score=res.f1_score,
            false_positive_rate=res.false_positive_rate,
            latency_ms=res.latency_ms,
            failure_reasons=json.loads(res.failure_reasons_json),
        )

    @classmethod
    def _format_run_response(
        cls, run: SimulationRun, result: Optional[SimulationResult]
    ) -> SimulationRunResponse:
        """Convert DB SimulationRun and optional result to response schema."""
        logs = []
        try:
            raw_logs = json.loads(run.execution_log_json)
            for l in raw_logs:
                logs.append(SimulationStepLog(**l))
        except Exception:
            pass

        res_dto = cls._format_result_response(result) if result else None

        return SimulationRunResponse(
            id=run.id,
            scenario_id=run.scenario_id,
            scenario_name=run.scenario_name,
            status=run.status,
            started_at=run.started_at.isoformat() if run.started_at else None,
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
            duration_ms=run.duration_ms or 0,
            summary=run.summary,
            execution_logs=logs,
            result=res_dto,
        )
