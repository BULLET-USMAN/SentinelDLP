"""API router endpoints for Phase 10: Cyberattack Simulation & Detection Validation Laboratory."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.simulation.scenario_registry import get_all_scenarios, get_scenario
from app.simulation.schemas import (
    GlobalDetectionMetrics,
    ScenarioDefinition,
    ScenarioRunRequest,
    SimulationReportResponse,
    SimulationResultResponse,
    SimulationRunResponse,
    SubsystemCoverageItem,
)
from app.simulation.services.coverage_service import CoverageService
from app.simulation.services.metrics_service import MetricsService
from app.simulation.services.reporting_service import ReportingService
from app.simulation.services.simulation_service import SimulationService

router = APIRouter(prefix="/simulation", tags=["Simulation Laboratory"])


@router.get("/scenarios", response_model=List[ScenarioDefinition])
def list_scenarios():
    """Retrieve all 11 predefined cyberattack and validation test scenarios."""
    return get_all_scenarios()


@router.get("/scenarios/{scenario_id}", response_model=ScenarioDefinition)
def get_scenario_detail(scenario_id: str):
    """Retrieve specifications for a single simulation scenario."""
    scen = get_scenario(scenario_id)
    if not scen:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found.",
        )
    return scen


@router.post("/runs", response_model=SimulationRunResponse)
def execute_scenario_run(
    request: ScenarioRunRequest,
    db: Session = Depends(get_db),
):
    """Execute a controlled attack simulation or validation scenario."""
    try:
        return SimulationService.start_run(db=db, request=request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute scenario run: {str(e)}",
        )


@router.get("/runs", response_model=List[SimulationRunResponse])
def list_runs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    scenario_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List historical simulation runs with optional filtering by scenario."""
    return SimulationService.list_runs(
        db=db, limit=limit, offset=offset, scenario_id=scenario_id
    )


@router.get("/runs/{run_id}", response_model=SimulationRunResponse)
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve detailed execution status and step logs for a specific run."""
    run = SimulationService.get_run(db=db, run_id=run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation run '{run_id}' not found.",
        )
    return run


@router.post("/runs/{run_id}/cancel")
def cancel_run(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Cancel an ongoing or pending simulation run."""
    success = SimulationService.cancel_run(db=db, run_id=run_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Run not found or cannot be cancelled.",
        )
    return {"cancelled": True, "run_id": run_id}


@router.get("/runs/{run_id}/results", response_model=SimulationResultResponse)
def get_run_results(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve granular detection evaluation results and statistical metrics for a run."""
    result = SimulationService.get_result_for_run(db=db, run_id=run_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No results found for simulation run '{run_id}'.",
        )
    return result


@router.get("/metrics", response_model=GlobalDetectionMetrics)
def get_global_metrics(
    db: Session = Depends(get_db),
):
    """Retrieve aggregated platform detection accuracy metrics and confusion matrix totals."""
    return MetricsService.get_global_metrics(db=db)


@router.get("/coverage", response_model=List[SubsystemCoverageItem])
def get_subsystem_coverage(
    db: Session = Depends(get_db),
):
    """Retrieve subsystem test coverage matrix across all 11 scenarios."""
    return CoverageService.get_coverage_matrix(db=db)


@router.get("/reports/{run_id}", response_model=SimulationReportResponse)
def get_simulation_report(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve formatted markdown security audit and validation report."""
    report = ReportingService.get_report(db=db, run_id=run_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation report for run '{run_id}' not found.",
        )
    return SimulationReportResponse(
        id=report.id,
        run_id=report.run_id,
        title=report.title,
        markdown_content=report.markdown_content,
        created_at=report.created_at.isoformat() if report.created_at else "",
    )
