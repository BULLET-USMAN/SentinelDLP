"""Network Detection Rules Registry for SentinelDLP (Phase 7).

Exports the full 10-rule detection suite.
"""

from typing import List
from app.network.detectors.base import BaseNetworkRule
from app.network.detectors.traffic_volume import UnusualOutboundVolumeRule
from app.network.detectors.connection_frequency import (
    MultiPortConnectionRule,
    RepeatedConnectionAttemptsRule,
)
from app.network.detectors.dns_anomalies import (
    DNSQueryPatternAnomaliesRule,
    UnusualDNSFrequencyRule,
)
from app.network.detectors.destination_analysis import UnfamiliarDestinationRule
from app.network.detectors.ids_alerts import SuricataSignatureAlertRule
from app.network.detectors.network_file_correlator import NetworkFileCorrelationRule
from app.network.detectors.visibility_gap import NetworkVisibilityGapRule
from app.network.detectors.multi_signal import MultiSignalNetworkRule

ALL_NETWORK_RULES: List[BaseNetworkRule] = [
    UnusualOutboundVolumeRule(),
    RepeatedConnectionAttemptsRule(),
    MultiPortConnectionRule(),
    UnusualDNSFrequencyRule(),
    DNSQueryPatternAnomaliesRule(),
    UnfamiliarDestinationRule(),
    SuricataSignatureAlertRule(),
    NetworkFileCorrelationRule(),
    NetworkVisibilityGapRule(),
    MultiSignalNetworkRule(),
]


def get_all_network_rules() -> List[BaseNetworkRule]:
    """Return all 10 registered network detection rules."""
    return list(ALL_NETWORK_RULES)


__all__ = [
    "BaseNetworkRule",
    "UnusualOutboundVolumeRule",
    "RepeatedConnectionAttemptsRule",
    "MultiPortConnectionRule",
    "UnusualDNSFrequencyRule",
    "DNSQueryPatternAnomaliesRule",
    "UnfamiliarDestinationRule",
    "SuricataSignatureAlertRule",
    "NetworkFileCorrelationRule",
    "NetworkVisibilityGapRule",
    "MultiSignalNetworkRule",
    "ALL_NETWORK_RULES",
    "get_all_network_rules",
]
