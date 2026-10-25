"""Network Traffic Analytics Service for SentinelDLP (Phase 7).

Aggregates stored network telemetry for dashboard visualizations:
- Connection counts and protocol distributions
- Time-series traffic volume trends (1h, 24h, 7d)
- Top destinations with byte volumes and threat flags
- DNS intelligence and anomaly metrics
- IDS alert severities and sensor health
"""

from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.network import NetworkEvent, NetworkSensor
from app.network.schemas import (
    DNSIntelligenceItem,
    DNSIntelligenceResponse,
    NetworkStatisticsResponse,
    TopDestinationItem,
    TrafficSummaryPoint,
    TrafficSummaryResponse,
)
from app.network.threat_intel import ThreatIntelService


class NetworkAnalyticsService:
    """Service layer computing network traffic metrics and analytics."""

    @staticmethod
    def get_statistics(db: Session) -> NetworkStatisticsResponse:
        """Compute high-level KPI metrics."""
        total_connections = (
            db.query(func.count(NetworkEvent.id))
            .filter(NetworkEvent.event_category.in_(["CONNECTION", "FLOW"]))
            .scalar() or 0
        )

        outbound_bytes = (
            db.query(func.sum(NetworkEvent.total_bytes))
            .filter(NetworkEvent.direction == "OUTBOUND")
            .scalar() or 0
        )

        dns_queries = (
            db.query(func.count(NetworkEvent.id))
            .filter(NetworkEvent.event_category == "DNS")
            .scalar() or 0
        )

        ids_alerts = (
            db.query(func.count(NetworkEvent.id))
            .filter(NetworkEvent.event_category == "ALERT")
            .scalar() or 0
        )

        active_sensors = (
            db.query(func.count(NetworkSensor.id))
            .filter(NetworkSensor.health_status == "ACTIVE", NetworkSensor.enabled.is_(True))
            .scalar() or 0
        )

        visibility_gaps = (
            db.query(func.count(NetworkSensor.id))
            .filter(NetworkSensor.health_status.in_(["VISIBILITY_GAP", "DEGRADED", "OFFLINE"]))
            .scalar() or 0
        )

        # Most prevalent transport protocol
        top_proto_row = (
            db.query(NetworkEvent.transport_protocol, func.count(NetworkEvent.id))
            .group_by(NetworkEvent.transport_protocol)
            .order_by(func.count(NetworkEvent.id).desc())
            .first()
        )
        top_proto = top_proto_row[0] if top_proto_row else "TCP"

        return NetworkStatisticsResponse(
            total_connections=total_connections,
            outbound_bytes_total=int(outbound_bytes),
            dns_queries_total=dns_queries,
            ids_alerts_total=ids_alerts,
            active_sensors_count=active_sensors,
            visibility_gaps_count=visibility_gaps,
            top_protocol=top_proto,
        )

    @staticmethod
    def get_traffic_summary(db: Session, interval: str = "24h") -> TrafficSummaryResponse:
        """Calculate traffic volume trend over time."""
        now = datetime.now(timezone.utc)
        if interval == "1h":
            start_time = now - timedelta(hours=1)
            bucket_delta = timedelta(minutes=5)
            buckets_count = 12
        elif interval == "7d":
            start_time = now - timedelta(days=7)
            bucket_delta = timedelta(hours=12)
            buckets_count = 14
        else:  # default 24h
            start_time = now - timedelta(hours=24)
            bucket_delta = timedelta(hours=2)
            buckets_count = 12

        events = (
            db.query(NetworkEvent.timestamp, NetworkEvent.total_bytes)
            .filter(NetworkEvent.timestamp >= start_time)
            .order_by(NetworkEvent.timestamp.asc())
            .all()
        )

        # Initialize time buckets
        bucket_points: List[TrafficSummaryPoint] = []
        tot_bytes = 0

        for i in range(buckets_count):
            b_start = start_time + (bucket_delta * i)
            b_end = b_start + bucket_delta
            b_bytes = sum((e.total_bytes or 0) for e in events if b_start <= e.timestamp < b_end)
            b_conns = sum(1 for e in events if b_start <= e.timestamp < b_end)
            tot_bytes += b_bytes
            bucket_points.append(
                TrafficSummaryPoint(
                    timestamp=b_start,
                    bytes_outbound=b_bytes,
                    connection_count=b_conns,
                )
            )

        return TrafficSummaryResponse(
            interval=interval,
            points=bucket_points,
            total_bytes=tot_bytes,
        )

    @staticmethod
    def get_top_destinations(db: Session, limit: int = 10) -> List[TopDestinationItem]:
        """Query top destination hosts/IPs with aggregated byte volumes and threat classifications."""
        results = (
            db.query(
                NetworkEvent.destination_ip,
                NetworkEvent.tls_sni,
                NetworkEvent.http_host,
                func.count(NetworkEvent.id).label("conns"),
                func.sum(func.coalesce(NetworkEvent.total_bytes, 0)).label("tot_bytes"),
                func.min(NetworkEvent.timestamp).label("first_seen"),
                func.max(NetworkEvent.timestamp).label("last_seen"),
            )
            .filter(NetworkEvent.direction == "OUTBOUND")
            .group_by(NetworkEvent.destination_ip, NetworkEvent.tls_sni, NetworkEvent.http_host)
            .order_by(func.sum(func.coalesce(NetworkEvent.total_bytes, 0)).desc())
            .limit(limit)
            .all()
        )

        items: List[TopDestinationItem] = []
        for r in results:
            dest_label = r.tls_sni or r.http_host or r.destination_ip
            matched_ind = ThreatIntelService.match_indicator(db, destination_ip=r.destination_ip, destination_host=dest_label)
            is_approved = ThreatIntelService.is_approved_destination(dest_label, db=db)

            if matched_ind:
                category = matched_ind.category
            elif is_approved:
                category = "TRUSTED"
            else:
                category = "UNKNOWN"

            # Check if destination has associated alerts
            has_alert = (
                db.query(NetworkEvent.id)
                .filter(
                    NetworkEvent.destination_ip == r.destination_ip,
                    NetworkEvent.event_category == "ALERT",
                )
                .first()
                is not None
            )

            items.append(
                TopDestinationItem(
                    destination=dest_label,
                    connection_count=r.conns,
                    total_bytes=int(r.tot_bytes or 0),
                    category=category,
                    has_alerts=has_alert,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                )
            )

        return items

    @staticmethod
    def get_dns_intelligence(db: Session, limit: int = 15) -> DNSIntelligenceResponse:
        """Aggregate DNS query activity and flag pattern anomalies."""
        dns_events = (
            db.query(NetworkEvent)
            .filter(NetworkEvent.event_category == "DNS", NetworkEvent.dns_query.isnot(None))
            .all()
        )

        total_queries = len(dns_events)
        queries_grouped: Dict[str, List[NetworkEvent]] = {}
        for e in dns_events:
            if e.dns_query:
                queries_grouped.setdefault(e.dns_query, []).append(e)

        sorted_queries = sorted(queries_grouped.items(), key=lambda item: len(item[1]), reverse=True)

        items: List[DNSIntelligenceItem] = []
        anomalous_count = 0

        for q_name, evts in sorted_queries[:limit]:
            nx_count = sum(1 for e in evts if e.dns_response_code == "NXDOMAIN")
            types = list({e.dns_query_type for e in evts if e.dns_query_type})
            is_anom = len(q_name) > 50 or nx_count >= 5
            anom_reason = None
            if len(q_name) > 50:
                anom_reason = "Unusually long domain name (>50 chars)"
            elif nx_count >= 5:
                anom_reason = f"High NXDOMAIN failure count ({nx_count})"

            if is_anom:
                anomalous_count += 1

            items.append(
                DNSIntelligenceItem(
                    query_name=q_name,
                    query_count=len(evts),
                    query_types=types,
                    nxdomain_count=nx_count,
                    is_anomalous=is_anom,
                    anomaly_reason=anom_reason,
                )
            )

        return DNSIntelligenceResponse(
            total_queries=total_queries,
            anomalous_queries_count=anomalous_count,
            frequent_domains=items,
        )
