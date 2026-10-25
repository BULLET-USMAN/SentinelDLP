"""Real-Time File Activity Monitoring API Endpoints (Phase 4).

Provides endpoints for monitoring lifecycle management (start/stop),
paginated historical activity audit, live statistics, and Server-Sent Events (SSE) streaming.
"""

import asyncio
from datetime import datetime
import json
import queue
from typing import AsyncGenerator, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.core.auth import AuthUser, require_admin, require_readonly
from app.core.config import settings
from app.db.session import get_db
from app.models.monitoring import FileActivityEvent, MonitoringConfiguration, MonitoringSession
from app.monitoring.manager import monitoring_manager
from app.monitoring.schemas import (
    FileActivityEventItem,
    MonitoringRootInfo,
    MonitoringStartRequest,
    MonitoringStatisticsResponse,
    MonitoringStatusResponse,
    MonitoringStopRequest,
    PaginatedEventsResponse,
)
from app.scanner.validators import SecurityBoundaryException

router = APIRouter()


@router.get(
    "/monitoring/roots",
    response_model=List[MonitoringRootInfo],
    summary="Get Authorized Monitoring Roots",
    description="Returns administrator-approved root directories available for real-time monitoring.",
    tags=["Real-Time Activity Monitoring"],
)
async def get_monitoring_roots(
    current_user: AuthUser = Depends(require_readonly),
) -> List[MonitoringRootInfo]:
    """Retrieve allowlisted monitoring roots and active status."""
    roots = settings.get_authorized_roots()
    result = []
    for root_id, meta in roots.items():
        is_active = monitoring_manager.is_active(root_id)
        session_id = monitoring_manager.get_active_session_id(root_id)
        result.append(
            MonitoringRootInfo(
                root_id=root_id,
                name=meta.get("name", root_id),
                path=meta.get("path", ""),
                description=meta.get("description", ""),
                is_active=is_active,
                session_id=session_id,
            )
        )
    return result


@router.get(
    "/monitoring/status",
    response_model=MonitoringStatusResponse,
    summary="Get Monitoring Status",
    description="Returns live operational status and session telemetry for a monitored root directory.",
    tags=["Real-Time Activity Monitoring"],
)
async def get_monitoring_status(
    root_id: Optional[str] = Query(None, description="Target root ID (defaults to primary authorized root)"),
    current_user: AuthUser = Depends(require_readonly),
) -> MonitoringStatusResponse:
    """Retrieve live monitoring status."""
    target_root = root_id or "synthetic_samples"
    return monitoring_manager.get_status(target_root)


@router.post(
    "/monitoring/start",
    response_model=MonitoringStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Start Real-Time Monitoring",
    description="Initiates real-time filesystem observation on an authorized root directory.",
    tags=["Real-Time Activity Monitoring"],
)
async def start_monitoring(
    request: MonitoringStartRequest,
    current_user: AuthUser = Depends(require_admin),
) -> MonitoringStatusResponse:
    """Start watcher on authorized root."""
    try:
        return monitoring_manager.start_monitoring(
            root_id=request.root_id,
            recursive=request.recursive,
        )
    except SecurityBoundaryException as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Boundary Violation: {err.message}",
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start monitoring: {str(err)}",
        )


@router.post(
    "/monitoring/stop",
    response_model=MonitoringStatusResponse,
    summary="Stop Real-Time Monitoring",
    description="Terminates real-time filesystem observation on an authorized root directory.",
    tags=["Real-Time Activity Monitoring"],
)
async def stop_monitoring(
    request: MonitoringStopRequest,
    current_user: AuthUser = Depends(require_admin),
) -> MonitoringStatusResponse:
    """Stop active watcher."""
    status_resp = monitoring_manager.stop_monitoring(request.root_id)
    if not status_resp:
        return monitoring_manager.get_status(request.root_id)
    return status_resp


@router.get(
    "/monitoring/events",
    response_model=PaginatedEventsResponse,
    summary="Get Paginated Activity Events",
    description="Returns historical filesystem activity events with multi-criteria filtering and pagination.",
    tags=["Real-Time Activity Monitoring"],
)
async def get_monitoring_events(
    page: int = Query(1, ge=1, description="Page index (1-based)"),
    size: int = Query(50, ge=1, le=500, description="Items per page"),
    root_id: Optional[str] = Query(None, description="Filter by root ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type (FILE_CREATED, FILE_MODIFIED, etc.)"),
    sensitivity: Optional[str] = Query(None, description="Filter by sensitivity classification (RESTRICTED, etc.)"),
    search: Optional[str] = Query(None, description="Filename substring search"),
    status: Optional[str] = Query(None, description="Filter by processing status"),
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_readonly),
) -> PaginatedEventsResponse:
    """Retrieve paginated activity events."""
    query = db.query(FileActivityEvent)

    if root_id:
        query = query.filter(FileActivityEvent.root_id == root_id.strip())

    if event_type:
        query = query.filter(FileActivityEvent.event_type == event_type.strip().upper())

    if sensitivity:
        query = query.filter(FileActivityEvent.sensitivity_label == sensitivity.strip().upper())

    if status:
        query = query.filter(FileActivityEvent.status == status.strip().lower())

    if search:
        query = query.filter(FileActivityEvent.relative_path.ilike(f"%{search.strip()}%"))

    total = query.count()
    offset = (page - 1) * size
    records = query.order_by(FileActivityEvent.occurred_at.desc()).offset(offset).limit(size).all()

    items = [
        FileActivityEventItem(
            id=r.id,
            root_id=r.root_id,
            event_type=r.event_type,
            is_directory=r.is_directory,
            relative_path=r.relative_path,
            previous_relative_path=r.previous_relative_path,
            occurred_at=r.occurred_at,
            collected_at=r.collected_at,
            processed_at=r.processed_at,
            status=r.status,
            associated_file_id=r.associated_file_id,
            sensitivity_label=r.sensitivity_label,
            file_type=r.file_type,
            size_bytes=r.size_bytes,
            sha256_hash=r.sha256_hash,
            event_source=r.event_source,
            error_category=r.error_category,
        )
        for r in records
    ]

    pages = (total + size - 1) // size if total > 0 else 0

    return PaginatedEventsResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/monitoring/events/{event_id}",
    response_model=FileActivityEventItem,
    summary="Get Activity Event Details",
    description="Returns full audit details for a specific filesystem activity event.",
    tags=["Real-Time Activity Monitoring"],
)
async def get_event_details(
    event_id: str,
    db: Session = Depends(get_db),
) -> FileActivityEventItem:
    """Retrieve detailed event record."""
    r = db.query(FileActivityEvent).filter(FileActivityEvent.id == event_id).first()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Activity event '{event_id}' not found",
        )

    return FileActivityEventItem(
        id=r.id,
        root_id=r.root_id,
        event_type=r.event_type,
        is_directory=r.is_directory,
        relative_path=r.relative_path,
        previous_relative_path=r.previous_relative_path,
        occurred_at=r.occurred_at,
        collected_at=r.collected_at,
        processed_at=r.processed_at,
        status=r.status,
        associated_file_id=r.associated_file_id,
        sensitivity_label=r.sensitivity_label,
        file_type=r.file_type,
        size_bytes=r.size_bytes,
        sha256_hash=r.sha256_hash,
        event_source=r.event_source,
        error_category=r.error_category,
    )


@router.get(
    "/monitoring/statistics",
    response_model=MonitoringStatisticsResponse,
    summary="Get Monitoring Statistics",
    description="Returns aggregate activity metrics across event types, processing states, and watcher health.",
    tags=["Real-Time Activity Monitoring"],
)
async def get_monitoring_statistics(
    root_id: Optional[str] = Query(None, description="Optional root filter"),
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_readonly),
) -> MonitoringStatisticsResponse:
    """Retrieve global or per-root event metrics."""
    query = db.query(FileActivityEvent)
    if root_id:
        query = query.filter(FileActivityEvent.root_id == root_id.strip())

    total = query.count()
    created = query.filter(FileActivityEvent.event_type.in_(("FILE_CREATED", "DIRECTORY_CREATED"))).count()
    modified = query.filter(FileActivityEvent.event_type.in_(("FILE_MODIFIED", "DIRECTORY_MODIFIED"))).count()
    deleted = query.filter(FileActivityEvent.event_type.in_(("FILE_DELETED", "DIRECTORY_DELETED"))).count()
    renamed = query.filter(FileActivityEvent.event_type.in_(("FILE_RENAMED", "FILE_MOVED", "DIRECTORY_RENAMED", "DIRECTORY_MOVED"))).count()

    processed = query.filter(FileActivityEvent.status == "processed").count()
    ignored = query.filter(FileActivityEvent.status == "ignored").count()
    failed = query.filter(FileActivityEvent.status == "failed").count()

    # Active watchers count
    roots = settings.get_authorized_roots()
    active_count = sum(1 for r_id in roots if monitoring_manager.is_active(r_id))

    return MonitoringStatisticsResponse(
        total_events=total,
        created_count=created,
        modified_count=modified,
        deleted_count=deleted,
        renamed_count=renamed,
        processed_count=processed,
        ignored_count=ignored,
        failed_count=failed,
        active_watchers_count=active_count,
        queue_backlog=0,
    )


@router.get(
    "/monitoring/events/stream",
    summary="Live Server-Sent Events (SSE) Stream",
    description="Subscribes to real-time filesystem activity events via SSE text/event-stream.",
    tags=["Real-Time Activity Monitoring"],
)
async def stream_monitoring_events(
    root_id: str = Query("synthetic_samples", description="Root ID to stream events for"),
    current_user: AuthUser = Depends(require_readonly),
) -> StreamingResponse:
    """Stream live events over HTTP using Server-Sent Events."""
    client_queue: queue.Queue[dict] = queue.Queue(maxsize=100)

    def sse_callback(event_data: dict) -> None:
        try:
            client_queue.put_nowait(event_data)
        except queue.Full:
            pass

    monitoring_manager.add_sse_listener(root_id, sse_callback)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Yield initial connection message
            yield f"event: connected\ndata: {json.dumps({'status': 'stream_active', 'root_id': root_id})}\n\n"
            while True:
                try:
                    # Check for queued events without blocking the async event loop indefinitely
                    event_data = await asyncio.to_thread(client_queue.get, timeout=1.0)
                    yield f"event: activity\ndata: {json.dumps(event_data)}\n\n"
                except queue.Empty:
                    # Send periodic keep-alive comment
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            monitoring_manager.remove_sse_listener(root_id, sse_callback)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
