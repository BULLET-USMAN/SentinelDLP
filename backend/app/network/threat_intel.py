"""Local Threat Intelligence and Destination Context Service for SentinelDLP (Phase 7).

Provides safe, offline matching for:
- Known internal enterprise networks (RFC 1918)
- Approved external destinations (Corporate allowlist)
- Administrator-configured threat indicators (IPs, domains, CIDRs)

Privacy Guarantee:
- Never contacts third-party threat intelligence APIs.
- Never sends organizational traffic metadata across the network.
- All lookups are local in-memory or PostgreSQL-backed.
"""

from datetime import datetime, timezone
import ipaddress
from typing import List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.exfiltration.policies import DEFAULT_APPROVED_DESTINATIONS
from app.models.network import ThreatIntelIndicator
from app.network.config import DEFAULT_INTERNAL_CIDRS


class ThreatIntelService:
    """Evaluates network endpoints against local baseline allowlists and threat indicators."""

    @staticmethod
    def is_internal_ip(ip_str: str) -> bool:
        """Check if an IPv4 or IPv6 address belongs to internal private/loopback ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if ip_obj.is_private or ip_obj.is_loopback:
                return True
            for cidr in DEFAULT_INTERNAL_CIDRS:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
        return False

    @staticmethod
    def is_approved_destination(destination: str, db: Optional[Session] = None) -> bool:
        """Check if a hostname, domain, or IP is in the authorized baseline allowlist."""
        dest_clean = destination.lower().strip()
        
        # 1. Check default corporate allowlist
        if any(allowed in dest_clean for allowed in DEFAULT_APPROVED_DESTINATIONS):
            return True

        # 2. Check internal ranges
        if ThreatIntelService.is_internal_ip(dest_clean):
            return True

        # 3. Check DB-backed allowlist indicators if session provided
        if db:
            allow_indicators = (
                db.query(ThreatIntelIndicator)
                .filter(ThreatIntelIndicator.category == "TRUSTED_ALLOWLIST")
                .all()
            )
            for ind in allow_indicators:
                if ind.indicator_type == "DOMAIN" and ind.indicator_value.lower() in dest_clean:
                    return True
                elif ind.indicator_type == "IPV4" and ind.indicator_value == dest_clean:
                    return True
                elif ind.indicator_type == "CIDR":
                    try:
                        net = ipaddress.ip_network(ind.indicator_value, strict=False)
                        if ipaddress.ip_address(dest_clean) in net:
                            return True
                    except ValueError:
                        continue

        return False

    @staticmethod
    def match_indicator(
        db: Session,
        destination_ip: str,
        destination_host: Optional[str] = None,
    ) -> Optional[ThreatIntelIndicator]:
        """Check if destination matches any active suspicious or malicious indicator."""
        now = datetime.now(timezone.utc)
        indicators = (
            db.query(ThreatIntelIndicator)
            .filter(
                ThreatIntelIndicator.category.in_(["MALICIOUS", "SUSPICIOUS", "DENIED"]),
            )
            .all()
        )

        for ind in indicators:
            if ind.expires_at and ind.expires_at < now:
                continue

            # IP Match
            if ind.indicator_type == "IPV4" and ind.indicator_value == destination_ip:
                return ind

            # CIDR Match
            if ind.indicator_type == "CIDR":
                try:
                    net = ipaddress.ip_network(ind.indicator_value, strict=False)
                    if ipaddress.ip_address(destination_ip) in net:
                        return ind
                except ValueError:
                    pass

            # Domain Match
            if ind.indicator_type == "DOMAIN" and destination_host:
                if ind.indicator_value.lower() in destination_host.lower():
                    return ind

        return None
