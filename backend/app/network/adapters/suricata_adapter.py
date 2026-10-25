"""Suricata EVE JSON Log Adapter for SentinelDLP (Phase 7).

Parses Suricata EVE JSON line-delimited telemetry:
- flow (Network flow statistics, bytes to server/client, duration)
- alert (IDS signatures, rule IDs, mapped severity tiers)
- dns (DNS queries and responses, supporting v1 and v2 schemas)
- tls (TLS SNI and protocol version)
- http (HTTP requests, methods, hosts)

Strict Privacy:
- Never imports complete HTTP bodies or raw sensitive authorization headers.
- Normalizes Suricata numerical severity (1=High, 2=Medium, 3=Low) into SentinelDLP severity bands.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Generator, Optional, Tuple
from app.network.schemas import NormalizedNetworkEvent


class SuricataAdapter:
    """Parses line-delimited Suricata EVE JSON records into NormalizedNetworkEvents."""

    @staticmethod
    def parse_timestamp(raw_ts: Any) -> datetime:
        """Convert Suricata ISO8601 timestamp string into timezone-aware UTC datetime."""
        if isinstance(raw_ts, str):
            try:
                # E.g. "2026-10-25T16:00:00.123456+0000" or with Z
                ts_clean = raw_ts.replace("Z", "+00:00")
                if len(ts_clean) > 5 and ts_clean[-5] in ("+", "-") and ":" not in ts_clean[-5:]:
                    ts_clean = ts_clean[:-2] + ":" + ts_clean[-2:]
                dt = datetime.fromisoformat(ts_clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def map_suricata_severity(raw_severity: Any) -> str:
        """Map Suricata numeric severity (1=Critical, 2=High, 3=Medium, 4=Low) into SentinelDLP bands."""
        try:
            sev_num = int(raw_severity)
            if sev_num == 1:
                return "CRITICAL"
            elif sev_num == 2:
                return "HIGH"
            elif sev_num == 3:
                return "MEDIUM"
            else:
                return "LOW"
        except (ValueError, TypeError):
            return "MEDIUM"

    @classmethod
    def parse_eve_record(
        cls, record: Dict[str, Any], sensor_id: str = "suricata-sensor-01"
    ) -> Optional[NormalizedNetworkEvent]:
        """Parse a single EVE JSON record into a NormalizedNetworkEvent."""
        event_type = record.get("event_type", "").lower()
        src_ip = record.get("src_ip")
        dest_ip = record.get("dest_ip")

        # Skip stats or metadata records without endpoints
        if not src_ip or not dest_ip:
            if event_type == "stats":
                return None
            return None

        src_port = record.get("src_port")
        dest_port = record.get("dest_port")
        proto = str(record.get("proto", "TCP")).upper()
        app_proto = record.get("app_proto")
        timestamp = cls.parse_timestamp(record.get("timestamp"))
        flow_id = str(record.get("flow_id")) if record.get("flow_id") is not None else None

        # Base fields
        category = "FLOW"
        total_bytes = None
        b_src = None
        b_dst = None
        duration = None
        alert_sig = None
        alert_sev = None
        dns_query = None
        dns_qtype = None
        dns_rcode = None
        tls_sni = None
        tls_ver = None
        http_method = None
        http_host = None
        http_uri = None

        if event_type == "alert":
            category = "ALERT"
            alert_obj = record.get("alert", {})
            alert_sig = alert_obj.get("signature")
            alert_sev = cls.map_suricata_severity(alert_obj.get("severity", 2))
        elif event_type == "dns":
            category = "DNS"
            dns_obj = record.get("dns", {})
            # Handle v1 vs v2 DNS schema
            if "query" in dns_obj and isinstance(dns_obj["query"], dict):
                dns_query = dns_obj["query"].get("rrname")
                dns_qtype = dns_obj["query"].get("rrtype")
            elif "queries" in dns_obj and isinstance(dns_obj["queries"], list) and dns_obj["queries"]:
                dns_query = dns_obj["queries"][0].get("rrname")
                dns_qtype = dns_obj["queries"][0].get("rrtype")
            elif "rrname" in dns_obj:
                dns_query = dns_obj.get("rrname")
                dns_qtype = dns_obj.get("rrtype")
            dns_rcode = dns_obj.get("rcode")
            if dns_query:
                dns_query = str(dns_query).lower().strip()
        elif event_type == "tls":
            category = "TLS"
            tls_obj = record.get("tls", {})
            sni = tls_obj.get("sni")
            tls_sni = str(sni).lower().strip() if sni else None
            tls_ver = tls_obj.get("version")
        elif event_type == "http":
            category = "HTTP"
            http_obj = record.get("http", {})
            http_method = http_obj.get("http_method")
            http_host = http_obj.get("hostname")
            raw_url = str(http_obj.get("url", ""))
            http_uri = raw_url.split("?")[0] if raw_url else None
        elif event_type == "flow":
            category = "FLOW"
            flow_obj = record.get("flow", {})
            b_src = flow_obj.get("bytes_toserver")
            b_dst = flow_obj.get("bytes_toclient")
            if b_src is not None or b_dst is not None:
                total_bytes = (b_src or 0) + (b_dst or 0)
            duration = float(flow_obj.get("age", 0))

        # Flow counters might also be present on other event types
        if total_bytes is None and "flow" in record and isinstance(record["flow"], dict):
            fl = record["flow"]
            b_src = fl.get("bytes_toserver")
            b_dst = fl.get("bytes_toclient")
            if b_src is not None or b_dst is not None:
                total_bytes = (b_src or 0) + (b_dst or 0)

        return NormalizedNetworkEvent(
            sensor_id=sensor_id,
            source_technology="SURICATA",
            original_event_id=flow_id,
            event_category=category,
            timestamp=timestamp,
            source_ip=str(src_ip),
            source_port=int(src_port) if src_port else None,
            destination_ip=str(dest_ip),
            destination_port=int(dest_port) if dest_port else None,
            transport_protocol=proto,
            application_protocol=str(app_proto).upper() if app_proto else None,
            direction="OUTBOUND",
            connection_duration_seconds=duration,
            bytes_source_to_dest=b_src,
            bytes_dest_to_source=b_dst,
            total_bytes=total_bytes,
            dns_query=dns_query,
            dns_query_type=dns_qtype,
            dns_response_code=dns_rcode,
            tls_sni=tls_sni,
            tls_version=tls_ver,
            http_method=http_method,
            http_host=http_host,
            http_uri_stem=http_uri,
            alert_signature=alert_sig,
            alert_severity=alert_sev,
            evidence_provenance="IMPORTED",
            capture_completeness="COMPLETE",
            is_simulated=False,
            metadata_json=json.dumps({"event_type": event_type, "pcap_cnt": record.get("pcap_cnt")}),
        )

    @classmethod
    def stream_parse_lines(
        cls, lines: Generator[str, None, None], sensor_id: str = "suricata-sensor-01"
    ) -> Generator[Tuple[Optional[NormalizedNetworkEvent], bool, Optional[str]], None, None]:
        """Stream line-by-line parsing of Suricata EVE JSON logs.

        Yields (NormalizedNetworkEvent, is_valid, error_msg).
        """
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
                event = cls.parse_eve_record(data, sensor_id=sensor_id)
                if event:
                    yield event, True, None
                else:
                    # Non-actionable or stats record
                    yield None, False, "Skipped record (stats or missing endpoints)"
            except json.JSONDecodeError as err:
                yield None, False, f"Malformed EVE JSON: {str(err)}"
            except Exception as err:
                yield None, False, f"Suricata parse error: {str(err)}"
