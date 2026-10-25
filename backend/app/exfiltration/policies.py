"""Policies, Baselines, and Thresholds for Exfiltration Correlation (Phase 6).

Contains detection constants, baseline approved destinations, archive file extensions,
and temporal correlation window specifications.
"""

from typing import List, Set

# Recognized archive extensions (content is NEVER assumed without verified extraction)
ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".bz2",
    ".xz",
}

# Supported temporal correlation windows in minutes
CORRELATION_WINDOWS_MINUTES: List[int] = [1, 5, 15, 30, 60]

# Approved / Trusted Destination Baselines (Allowlist)
# Transfers to these destinations are not flagged as UNFAMILIAR
DEFAULT_APPROVED_DESTINATIONS: Set[str] = {
    "backup.internal.corp",
    "updates.microsoft.com",
    "github.com",
    "storage.googleapis.com",
    "dlp-trusted-vault.internal",
    "corp-intranet.local",
}

# Quantitative Detection Thresholds
THRESHOLD_HIGH_VOLUME_SENSITIVE_COUNT: int = 5  # >= 5 sensitive file events in window
THRESHOLD_UNUSUAL_TRANSFER_BYTES: int = 5 * 1024 * 1024  # 5 MB
THRESHOLD_CRITICAL_TRANSFER_BYTES: int = 50 * 1024 * 1024  # 50 MB
THRESHOLD_REPEATED_TRANSFER_COUNT: int = 3  # >= 3 outbound transfers in window

# Window duration defaults
DEFAULT_CORRELATION_WINDOW_MINUTES: int = 15


def is_archive_file(file_path: str) -> bool:
    """Check if the provided file path ends with a recognized archive extension."""
    if not file_path:
        return False
    lower_path = file_path.lower()
    return any(lower_path.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


def is_destination_approved(destination: str, custom_allowlist: Set[str] = None) -> bool:
    """Check if the given host or destination URL is in the approved baseline allowlist."""
    if not destination:
        return False
    allowlist = custom_allowlist if custom_allowlist is not None else DEFAULT_APPROVED_DESTINATIONS
    dest_lower = destination.lower().strip()
    return any(allowed in dest_lower for allowed in allowlist)
