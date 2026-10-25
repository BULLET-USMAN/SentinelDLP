"""Exfiltration Detection Rule Registry for SentinelDLP (Phase 6).

Exports the complete 8-rule detection suite.
"""

from typing import List
from app.exfiltration.rules.base import BaseExfiltrationRule
from app.exfiltration.rules.bulk_sensitive_activity import HighVolumeSensitiveActivityRule
from app.exfiltration.rules.archive_activity import (
    ArchiveFollowedByTransferRule,
    SensitiveActivityArchiveCreationRule,
)
from app.exfiltration.rules.transfer_correlation import (
    RepeatedOutboundTransfersRule,
    UnusualTransferVolumeRule,
)
from app.exfiltration.rules.unusual_destination import UnfamiliarDestinationRule
from app.exfiltration.rules.multi_signal import (
    InsufficientEvidenceRule,
    MultiSignalExfiltrationRule,
)

ALL_EXFILTRATION_RULES: List[BaseExfiltrationRule] = [
    HighVolumeSensitiveActivityRule(),
    SensitiveActivityArchiveCreationRule(),
    ArchiveFollowedByTransferRule(),
    UnusualTransferVolumeRule(),
    UnfamiliarDestinationRule(),
    RepeatedOutboundTransfersRule(),
    MultiSignalExfiltrationRule(),
    InsufficientEvidenceRule(),
]


def get_all_exfiltration_rules() -> List[BaseExfiltrationRule]:
    """Return initialized rule instances."""
    return list(ALL_EXFILTRATION_RULES)


__all__ = [
    "BaseExfiltrationRule",
    "HighVolumeSensitiveActivityRule",
    "SensitiveActivityArchiveCreationRule",
    "ArchiveFollowedByTransferRule",
    "UnusualTransferVolumeRule",
    "UnfamiliarDestinationRule",
    "RepeatedOutboundTransfersRule",
    "MultiSignalExfiltrationRule",
    "InsufficientEvidenceRule",
    "ALL_EXFILTRATION_RULES",
    "get_all_exfiltration_rules",
]
