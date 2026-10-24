"""Monitoring Package for SentinelDLP (Phase 4)."""

from app.monitoring.deduplication import EventDeduplicator
from app.monitoring.event_normalizer import NormalizedEvent, normalize_watchdog_event
from app.monitoring.event_processor import EventProcessor
from app.monitoring.event_queue import BoundedEventQueue
from app.monitoring.manager import MonitoringManager, monitoring_manager
from app.monitoring.schemas import (
    FileActivityEventItem,
    MonitoringRootInfo,
    MonitoringStartRequest,
    MonitoringStatisticsResponse,
    MonitoringStatusResponse,
    MonitoringStopRequest,
    PaginatedEventsResponse,
)
from app.monitoring.watcher import MonitoringWatcher, SentinelFileSystemEventHandler

__all__ = [
    "EventDeduplicator",
    "NormalizedEvent",
    "normalize_watchdog_event",
    "EventProcessor",
    "BoundedEventQueue",
    "MonitoringManager",
    "monitoring_manager",
    "MonitoringWatcher",
    "SentinelFileSystemEventHandler",
    "FileActivityEventItem",
    "MonitoringRootInfo",
    "MonitoringStartRequest",
    "MonitoringStatisticsResponse",
    "MonitoringStatusResponse",
    "MonitoringStopRequest",
    "PaginatedEventsResponse",
]
