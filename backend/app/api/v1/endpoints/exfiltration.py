"""Exfiltration Detection & Event Correlation Endpoints for SentinelDLP (Phase 6).

Provides RESTful endpoints for:
- Querying and managing exfiltration investigations and triage lifecycle.
- Chronological forensic timeline synthesis with explicit provenance badges.
- Ingestion and simulation of outbound transfer telemetry (LAB_SIMULATED).
- live metrics, statistics, and rule catalog inspection.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.exfiltration.engine import exfiltration_engine
from app.exfiltration.schemas import (
    ExfiltrationCorrelateRequest,
    ExfiltrationCorrelateResponse,
    ExfiltrationInvestigationDetailResponse,
    ExfiltrationInvestigationResponse,
    ExfiltrationRuleDefinitionResponse,
    ExfiltrationStatisticsResponse,
    ExfiltrationTimelineItem,
    InvestigationEvidenceLinkResponse,
    InvestigationStatusUpdate,
    TransferEventBatchImport,
    TransferEventCreate,
    TransferEventResponse,
)
from app.exfiltration.services.investigation_service import InvestigationService
from app.exfiltration.services.transfer_service import TransferService
from app.exfiltration.timeline import build_investigation_timeline
from app.models.monitoring import FileActivityEvent
from app.models.exfiltration import TransferEvent

router = APIRouter(prefix="/exfiltration", tags=["Data Exfiltration Correlation"])


@router.get(
    "/investigations",
    response_model=List[ExfiltrationInvestigationResponse],
    summary="List Exfiltration Investigations",
    description="Retrieve a paginated, filterable list of exfiltration investigations.",
)
def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status (OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, INCONCLUSIVE)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    confidence: Optional[str] = Query(None, description="Filter by confidence (LOW, MEDIUM, HIGH)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[ExfiltrationInvestigationResponse]:
    results, _ = InvestigationService.list_investigations(
        db=db,
        status=status,
        severity=severity,
        confidence=confidence,
        limit=limit,
        offset=offset,
    )
    return results


@router.get(
    "/investigations/{investigation_id}",
    response_model=ExfiltrationInvestigationDetailResponse,
    summary="Get Investigation Details",
    description="Retrieve complete investigation details, including correlation records and evidence links.",
)
def get_investigation_details(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> ExfiltrationInvestigationDetailResponse:
    inv = InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return inv


@router.get(
    "/investigations/{investigation_id}/timeline",
    response_model=List[ExfiltrationTimelineItem],
    summary="Get Investigation Timeline",
    description="Generate a chronological forensic timeline with provenance labels and relationship tags.",
)
def get_investigation_timeline(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> List[ExfiltrationTimelineItem]:
    inv = InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return build_investigation_timeline(inv)


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=List[InvestigationEvidenceLinkResponse],
    summary="Get Investigation Evidence",
    description="Retrieve all granular evidence records linked to this investigation.",
)
def get_investigation_evidence(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> List[InvestigationEvidenceLinkResponse]:
    inv = InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return inv.evidence_links


@router.patch(
    "/investigations/{investigation_id}/status",
    response_model=ExfiltrationInvestigationDetailResponse,
    summary="Update Investigation Status",
    description="Update investigation triage state, assign analyst, or record audit notes.",
)
def update_investigation_status(
    investigation_id: str,
    payload: InvestigationStatusUpdate,
    db: Session = Depends(get_db),
) -> ExfiltrationInvestigationDetailResponse:
    updated = InvestigationService.update_status(
        db=db,
        investigation_id=investigation_id,
        payload=payload,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return updated


@router.get(
    "/statistics",
    response_model=ExfiltrationStatisticsResponse,
    summary="Exfiltration Dashboard Statistics",
    description="Retrieve live aggregate metrics, open cases, and active rules count.",
)
def get_exfiltration_statistics(
    db: Session = Depends(get_db),
) -> ExfiltrationStatisticsResponse:
    return InvestigationService.get_statistics(db=db)


@router.get(
    "/rules",
    response_model=List[ExfiltrationRuleDefinitionResponse],
    summary="List Exfiltration Correlation Rules",
    description="Retrieve metadata for all 8 deterministic detection rules.",
)
def list_exfiltration_rules() -> List[ExfiltrationRuleDefinitionResponse]:
    return exfiltration_engine.get_registered_rules()


@router.post(
    "/correlate",
    response_model=ExfiltrationCorrelateResponse,
    summary="Run Exfiltration Correlation",
    description="Trigger a bounded temporal correlation pass across recent telemetry.",
)
def trigger_correlation(
    payload: ExfiltrationCorrelateRequest = ExfiltrationCorrelateRequest(),
    db: Session = Depends(get_db),
) -> ExfiltrationCorrelateResponse:
    investigations = exfiltration_engine.execute_correlation(
        db=db,
        window_minutes=payload.window_minutes,
        endpoint_id=payload.endpoint_id or "endpoint-alpha-01",
    )
    transfer_count = db.query(TransferEvent).count()
    file_count = db.query(FileActivityEvent).count()

    return ExfiltrationCorrelateResponse(
        investigations_created=len(investigations),
        rules_evaluated=8,
        transfer_events_analyzed=transfer_count,
        file_events_analyzed=file_count,
        window_minutes=payload.window_minutes,
        timestamp=datetime.now(timezone.utc),
    )


@router.post(
    "/transfers/import",
    response_model=List[TransferEventResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Batch Import Transfer Events",
    description="Ingest outbound transfer telemetry from simulated harness or external collector.",
)
def import_transfer_events(
    payload: TransferEventBatchImport,
    db: Session = Depends(get_db),
) -> List[TransferEventResponse]:
    return TransferService.batch_import_transfers(db=db, events=payload.events)


@router.post(
    "/transfers/simulate",
    response_model=List[TransferEventResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Simulate Lab Exfiltration Scenario",
    description="Generate synthetic LAB_SIMULATED outbound transfer telemetry for demonstration.",
)
def simulate_transfer_scenario(
    scenario_type: str = Query("cloud_exfiltration", description="cloud_exfiltration, chunked_exfiltration, or benign_sync"),
    db: Session = Depends(get_db),
) -> List[TransferEventResponse]:
    return TransferService.generate_lab_synthetic_scenarios(db=db, scenario_type=scenario_type)


@router.get(
    "/transfers",
    response_model=List[TransferEventResponse],
    summary="List Outbound Transfer Events",
    description="Query outbound transfer events recorded in the system.",
)
def list_transfer_events(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    destination_host: Optional[str] = Query(None),
    is_simulated: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
) -> List[TransferEventResponse]:
    transfers, _ = TransferService.list_transfers(
        db=db,
        limit=limit,
        offset=offset,
        destination_host=destination_host,
        is_simulated=is_simulated,
    )
    return transfers
