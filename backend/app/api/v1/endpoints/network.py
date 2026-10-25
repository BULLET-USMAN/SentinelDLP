"""Network Monitoring and Threat Intelligence Endpoints for SentinelDLP (Phase 7).

Provides RESTful endpoints for:
- Querying normalized network telemetry (connections, DNS, HTTP, TLS).
- Network sensor health, ingestion jobs, and visibility gap auditing.
- Traffic analytics and time-series outbound byte summaries.
- Suricata IDS alert reference inspections.
- Bounded offline PCAP and log ingestion.
- Local threat intelligence indicators and destination classification.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.auth import AuthUser, require_admin, require_readonly
from app.db.session import get_db
from app.models.network import (
    NetworkAlertReference,
    NetworkEvent,
    NetworkIngestionJob,
    NetworkSensor,
    ThreatIntelIndicator,
)
from app.network.engine import network_engine
from app.network.schemas import (
    DNSIntelligenceResponse,
    NetworkAlertReferenceResponse,
    NetworkEventResponse,
    NetworkIngestRequest,
    NetworkIngestResponse,
    NetworkIngestionJobResponse,
    NetworkRuleDefinitionResponse,
    NetworkSensorResponse,
    NetworkSimulateRequest,
    NetworkStatisticsResponse,
    PaginatedNetworkEventsResponse,
    ThreatIntelIndicatorCreate,
    ThreatIntelIndicatorResponse,
    TopDestinationItem,
    TrafficSummaryResponse,
)
from app.network.services.analytics_service import NetworkAnalyticsService

router = APIRouter(prefix="/network", tags=["Network Intelligence"])


@router.get(
    "/status",
    summary="Get Network Monitoring Status",
    description="Retrieve high-level sensor status, health, and coverage warnings.",
)
def get_network_status(db: Session = Depends(get_db)):
    sensors = db.query(NetworkSensor).all()
    active_count = sum(1 for s in sensors if s.health_status == "ACTIVE" and s.enabled)
    gaps = [s for s in sensors if s.health_status in ("VISIBILITY_GAP", "DEGRADED", "OFFLINE")]
    return {
        "status": "degraded" if gaps else "operational",
        "sensors_active": active_count,
        "sensors_total": len(sensors),
        "visibility_gaps_count": len(gaps),
        "visibility_gaps": [
            {"sensor_id": s.sensor_id, "technology": s.technology, "reason": s.coverage_gap_reason}
            for s in gaps
        ],
        "timestamp": datetime.now(timezone.utc),
    }


@router.get(
    "/sensors",
    response_model=List[NetworkSensorResponse],
    summary="List Network Sensors",
    description="Retrieve registered Zeek, Suricata, and PCAP monitoring sensors.",
)
def list_sensors(db: Session = Depends(get_db)) -> List[NetworkSensorResponse]:
    return db.query(NetworkSensor).order_by(NetworkSensor.created_at.asc()).all()


@router.get(
    "/connections",
    response_model=PaginatedNetworkEventsResponse,
    summary="List Network Connections",
    description="Retrieve paginated, filterable network flow and connection telemetry.",
)
def list_connections(
    source_ip: Optional[str] = Query(None),
    destination_ip: Optional[str] = Query(None),
    transport_protocol: Optional[str] = Query(None),
    min_bytes: Optional[int] = Query(None, ge=0),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> PaginatedNetworkEventsResponse:
    query = db.query(NetworkEvent).filter(NetworkEvent.event_category.in_(["CONNECTION", "FLOW"]))
    if source_ip:
        query = query.filter(NetworkEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NetworkEvent.destination_ip == destination_ip)
    if transport_protocol:
        query = query.filter(NetworkEvent.transport_protocol == transport_protocol.upper())
    if min_bytes is not None:
        query = query.filter(NetworkEvent.total_bytes >= min_bytes)

    total = query.count()
    items = query.order_by(NetworkEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return PaginatedNetworkEventsResponse(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/dns",
    response_model=DNSIntelligenceResponse,
    summary="Get DNS Intelligence & Analytics",
    description="Query frequency distributions, NXDOMAIN ratios, and pattern anomalies.",
)
def get_dns_intelligence(
    limit: int = Query(15, ge=1, le=50),
    db: Session = Depends(get_db),
) -> DNSIntelligenceResponse:
    return NetworkAnalyticsService.get_dns_intelligence(db, limit=limit)


@router.get(
    "/alerts",
    response_model=List[NetworkAlertReferenceResponse],
    summary="List Network IDS Alerts",
    description="Retrieve normalized IDS alerts (Suricata signatures and Zeek notices).",
)
def list_network_alerts(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[NetworkAlertReferenceResponse]:
    return (
        db.query(NetworkAlertReference)
        .order_by(NetworkAlertReference.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get(
    "/statistics",
    response_model=NetworkStatisticsResponse,
    summary="Get Network Dashboard Statistics",
    description="Retrieve aggregate metrics for KPI tiles.",
)
def get_network_statistics(db: Session = Depends(get_db)) -> NetworkStatisticsResponse:
    return NetworkAnalyticsService.get_statistics(db)


@router.get(
    "/traffic-summary",
    response_model=TrafficSummaryResponse,
    summary="Get Outbound Traffic Summary",
    description="Calculate time-series traffic volume trends for 1h, 24h, or 7d intervals.",
)
def get_traffic_summary(
    interval: str = Query("24h", pattern=r"^(1h|24h|7d)$"),
    db: Session = Depends(get_db),
) -> TrafficSummaryResponse:
    return NetworkAnalyticsService.get_traffic_summary(db, interval=interval)


@router.get(
    "/destinations",
    response_model=List[TopDestinationItem],
    summary="Get Top Outbound Destinations",
    description="Retrieve highest-volume destination hosts and IPs with threat intel badges.",
)
def get_top_destinations(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> List[TopDestinationItem]:
    return NetworkAnalyticsService.get_top_destinations(db, limit=limit)


@router.get(
    "/ingestion-jobs",
    response_model=List[NetworkIngestionJobResponse],
    summary="List Ingestion Jobs",
    description="Retrieve audit history of log and PCAP ingestion batches.",
)
def list_ingestion_jobs(
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[NetworkIngestionJobResponse]:
    return (
        db.query(NetworkIngestionJob)
        .order_by(NetworkIngestionJob.start_time.desc())
        .limit(limit)
        .all()
    )


@router.get(
    "/rules",
    response_model=List[NetworkRuleDefinitionResponse],
    summary="List Network Detection Rules",
    description="Retrieve specifications of all 10 active network detection rules (NET-001 through NET-010).",
)
def list_network_rules() -> List[NetworkRuleDefinitionResponse]:
    return network_engine.get_registered_rules()


@router.post(
    "/ingest",
    response_model=NetworkIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Network Log or PCAP",
    description="Protected ingestion endpoint for preapproved files or streaming raw log content.",
)
def ingest_network_telemetry(
    payload: NetworkIngestRequest,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_admin),
) -> NetworkIngestResponse:
    return network_engine.ingest_telemetry(
        db=db,
        sensor_id=payload.sensor_id,
        source_format=payload.source_format,
        file_path=payload.file_path,
        raw_content=payload.raw_content,
    )


@router.post(
    "/simulate",
    response_model=NetworkIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Simulate Synthetic Network Scenario",
    description="Generate realistic Zeek and Suricata telemetry for test and evaluation.",
)
def simulate_network_scenario(
    payload: NetworkSimulateRequest = NetworkSimulateRequest(),
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_admin),
) -> NetworkIngestResponse:
    return network_engine.simulate_scenario(db=db, scenario_type=payload.scenario_type)


@router.get(
    "/threat-intel/indicators",
    response_model=List[ThreatIntelIndicatorResponse],
    summary="List Threat Intel Indicators",
    description="Retrieve administrator-configured allowlist and threat indicators.",
)
def list_threat_intel_indicators(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[ThreatIntelIndicatorResponse]:
    return db.query(ThreatIntelIndicator).order_by(ThreatIntelIndicator.created_at.desc()).limit(limit).all()


@router.post(
    "/threat-intel/indicators",
    response_model=ThreatIntelIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Threat Intel Indicator",
    description="Add a local indicator (IP, Domain, CIDR) to the local destination context table.",
)
def create_threat_intel_indicator(
    payload: ThreatIntelIndicatorCreate,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_admin),
) -> ThreatIntelIndicatorResponse:
    ind = ThreatIntelIndicator(
        indicator_type=payload.indicator_type.upper(),
        indicator_value=payload.indicator_value.strip().lower(),
        category=payload.category.upper(),
        source_feed=payload.source_feed,
        confidence=payload.confidence.upper(),
        description=payload.description,
        created_at=datetime.now(timezone.utc),
    )
    db.add(ind)
    db.commit()
    db.refresh(ind)
    return ind
