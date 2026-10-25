"""Zeek Log Ingestion Adapter for SentinelDLP (Phase 7).

Parses Zeek JSON logs:
- conn.log (Connection metadata, durations, byte counts, directions)
- dns.log (DNS queries, record types, response codes)
- http.log (HTTP requests, methods, hosts, URI stems)
- ssl.log / tls.log (TLS SNI, protocol versions, ciphers)

Strict Principles:
- Streaming line-by-line parsing: large logs never loaded entirely into memory.
- Graceful handling of missing optional fields, malformed lines, and unexpected types.
- Zero extraction of raw HTTP payload bodies or sensitive credentials.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Generator, Optional, Tuple
from app.network.schemas import NormalizedNetworkEvent


class ZeekAdapter:
    """Parses line-delimited Zeek JSON log formats into NormalizedNetworkEvents."""

    @staticmethod
    def parse_timestamp(raw_ts: Any) -> datetime:
        """Convert Zeek float epoch or ISO timestamp into timezone-aware UTC datetime."""
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
        elif isinstance(raw_ts, str):
            try:
                # Check for float in string
                return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
            except ValueError:
                # Fallback to ISO string
                try:
                    dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    pass
        return datetime.now(timezone.utc)

    @classmethod
    def parse_conn_record(
        cls, record: Dict[str, Any], sensor_id: str = "zeek-sensor-01"
    ) -> Optional[NormalizedNetworkEvent]:
        """Parse a single Zeek conn.log JSON record."""
        orig_h = record.get("id.orig_h") or record.get("orig_h") or record.get("id", {}).get("orig_h")
        resp_h = record.get("id.resp_h") or record.get("resp_h") or record.get("id", {}).get("resp_h")
        if not orig_h or not resp_h:
            return None

        orig_p = record.get("id.orig_p") or record.get("orig_p") or record.get("id", {}).get("orig_p")
        resp_p = record.get("id.resp_p") or record.get("resp_p") or record.get("id", {}).get("resp_p")

        orig_bytes = record.get("orig_bytes")
        resp_bytes = record.get("resp_bytes")
        b_src = int(orig_bytes) if orig_bytes is not None and str(orig_bytes).isdigit() else 0
        b_dst = int(resp_bytes) if resp_bytes is not None and str(resp_bytes).isdigit() else 0
        tot_bytes = b_src + b_dst

        duration = record.get("duration")
        duration_sec = float(duration) if duration is not None and isinstance(duration, (int, float)) else None

        proto = str(record.get("proto", "TCP")).upper()
        service = record.get("service")
        app_proto = str(service).upper() if service and service != "-" else None

        return NormalizedNetworkEvent(
            sensor_id=sensor_id,
            source_technology="ZEEK",
            original_event_id=record.get("uid"),
            event_category="CONNECTION",
            timestamp=cls.parse_timestamp(record.get("ts")),
            source_ip=str(orig_h),
            source_port=int(orig_p) if orig_p else None,
            destination_ip=str(resp_h),
            destination_port=int(resp_p) if resp_p else None,
            transport_protocol=proto,
            application_protocol=app_proto,
            direction="OUTBOUND",
            connection_duration_seconds=duration_sec,
            bytes_source_to_dest=b_src,
            bytes_dest_to_source=b_dst,
            total_bytes=tot_bytes,
            evidence_provenance="IMPORTED",
            capture_completeness="COMPLETE",
            is_simulated=False,
            metadata_json=json.dumps({"conn_state": record.get("conn_state"), "history": record.get("history")}),
        )

    @classmethod
    def parse_dns_record(
        cls, record: Dict[str, Any], sensor_id: str = "zeek-sensor-01"
    ) -> Optional[NormalizedNetworkEvent]:
        """Parse a single Zeek dns.log JSON record."""
        orig_h = record.get("id.orig_h") or record.get("id", {}).get("orig_h")
        resp_h = record.get("id.resp_h") or record.get("id", {}).get("resp_h")
        if not orig_h or not resp_h:
            return None

        orig_p = record.get("id.orig_p") or record.get("id", {}).get("orig_p")
        resp_p = record.get("id.resp_p") or record.get("id", {}).get("resp_p")

        query = record.get("query")
        if not query or query == "-":
            return None

        return NormalizedNetworkEvent(
            sensor_id=sensor_id,
            source_technology="ZEEK",
            original_event_id=record.get("uid"),
            event_category="DNS",
            timestamp=cls.parse_timestamp(record.get("ts")),
            source_ip=str(orig_h),
            source_port=int(orig_p) if orig_p else None,
            destination_ip=str(resp_h),
            destination_port=int(resp_p) if resp_p else 53,
            transport_protocol=str(record.get("proto", "UDP")).upper(),
            application_protocol="DNS",
            direction="OUTBOUND",
            dns_query=str(query).lower().strip(),
            dns_query_type=record.get("qtype_name"),
            dns_response_code=record.get("rcode_name"),
            evidence_provenance="IMPORTED",
            capture_completeness="COMPLETE",
            is_simulated=False,
            metadata_json=json.dumps({"answers": record.get("answers", [])}),
        )

    @classmethod
    def parse_ssl_record(
        cls, record: Dict[str, Any], sensor_id: str = "zeek-sensor-01"
    ) -> Optional[NormalizedNetworkEvent]:
        """Parse a single Zeek ssl.log or tls.log JSON record."""
        orig_h = record.get("id.orig_h") or record.get("id", {}).get("orig_h")
        resp_h = record.get("id.resp_h") or record.get("id", {}).get("resp_h")
        if not orig_h or not resp_h:
            return None

        orig_p = record.get("id.orig_p") or record.get("id", {}).get("orig_p")
        resp_p = record.get("id.resp_p") or record.get("id", {}).get("resp_p")

        server_name = record.get("server_name")
        sni = str(server_name).lower().strip() if server_name and server_name != "-" else None

        return NormalizedNetworkEvent(
            sensor_id=sensor_id,
            source_technology="ZEEK",
            original_event_id=record.get("uid"),
            event_category="TLS",
            timestamp=cls.parse_timestamp(record.get("ts")),
            source_ip=str(orig_h),
            source_port=int(orig_p) if orig_p else None,
            destination_ip=str(resp_h),
            destination_port=int(resp_p) if resp_p else 443,
            transport_protocol="TCP",
            application_protocol="TLS",
            direction="OUTBOUND",
            tls_sni=sni,
            tls_version=record.get("version"),
            evidence_provenance="IMPORTED",
            capture_completeness="COMPLETE",
            is_simulated=False,
            metadata_json=json.dumps({"cipher": record.get("cipher")}),
        )

    @classmethod
    def parse_http_record(
        cls, record: Dict[str, Any], sensor_id: str = "zeek-sensor-01"
    ) -> Optional[NormalizedNetworkEvent]:
        """Parse a single Zeek http.log JSON record."""
        orig_h = record.get("id.orig_h") or record.get("id", {}).get("orig_h")
        resp_h = record.get("id.resp_h") or record.get("id", {}).get("resp_h")
        if not orig_h or not resp_h:
            return None

        orig_p = record.get("id.orig_p") or record.get("id", {}).get("orig_p")
        resp_p = record.get("id.resp_p") or record.get("id", {}).get("resp_p")

        raw_uri = str(record.get("uri", ""))
        clean_stem = raw_uri.split("?")[0] if raw_uri else None  # Strictly strip query params

        return NormalizedNetworkEvent(
            sensor_id=sensor_id,
            source_technology="ZEEK",
            original_event_id=record.get("uid"),
            event_category="HTTP",
            timestamp=cls.parse_timestamp(record.get("ts")),
            source_ip=str(orig_h),
            source_port=int(orig_p) if orig_p else None,
            destination_ip=str(resp_h),
            destination_port=int(resp_p) if resp_p else 80,
            transport_protocol="TCP",
            application_protocol="HTTP",
            direction="OUTBOUND",
            http_method=record.get("method"),
            http_host=record.get("host"),
            http_uri_stem=clean_stem,
            total_bytes=record.get("response_body_len"),
            evidence_provenance="IMPORTED",
            capture_completeness="COMPLETE",
            is_simulated=False,
            metadata_json=json.dumps({"status_code": record.get("status_code"), "user_agent": record.get("user_agent")}),
        )

    @classmethod
    def stream_parse_lines(
        cls, lines: Generator[str, None, None], format_type: str, sensor_id: str = "zeek-sensor-01"
    ) -> Generator[Tuple[Optional[NormalizedNetworkEvent], bool, Optional[str]], None, None]:
        """Stream line-by-line parsing of Zeek logs.

        Yields (NormalizedNetworkEvent, is_valid, error_msg).
        """
        parser_map = {
            "ZEEK_CONN": cls.parse_conn_record,
            "ZEEK_DNS": cls.parse_dns_record,
            "ZEEK_SSL": cls.parse_ssl_record,
            "ZEEK_TLS": cls.parse_ssl_record,
            "ZEEK_HTTP": cls.parse_http_record,
        }
        parser = parser_map.get(format_type.upper(), cls.parse_conn_record)

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            try:
                data = json.loads(line_str)
                event = parser(data, sensor_id=sensor_id)
                if event:
                    yield event, True, None
                else:
                    yield None, False, "Missing required IP endpoints or query fields"
            except json.JSONDecodeError as err:
                yield None, False, f"Malformed JSON: {str(err)}"
            except Exception as err:
                yield None, False, f"Parsing exception: {str(err)}"
