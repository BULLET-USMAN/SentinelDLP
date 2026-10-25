"""Local, Offline MITRE ATT&CK Enterprise Catalog for SentinelDLP.

Provides validated references and strict anti-hallucination validation for
MITRE ATT&CK tactics and techniques relevant to Data Loss Prevention (DLP) and
Exfiltration detection.
"""

from typing import Dict, List, Optional, Any


MITRE_CATALOG: Dict[str, Dict[str, Any]] = {
    "T1074.001": {
        "technique_id": "T1074.001",
        "technique_name": "Data Staged: Local Data Staging",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1074/001/",
        "description": "Adversaries may stage collected data in a central location or directory prior to exfiltration.",
        "detection_context": "Observed when multiple sensitive documents are copied, modified, or aggregated into temporary folders or staging directories.",
    },
    "T1560.001": {
        "technique_id": "T1560.001",
        "technique_name": "Archive Collected Data: Archive via Utility",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1560/001/",
        "description": "Adversaries may compress or encrypt data using utility programs (zip, tar, 7z) prior to exfiltration.",
        "detection_context": "Observed when archive files are generated immediately following sensitive file modification or aggregation.",
    },
    "T1567.002": {
        "technique_id": "T1567.002",
        "technique_name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1567/002/",
        "description": "Adversaries may exfiltrate data to a cloud storage service rather than through their primary command and control channel.",
        "detection_context": "Observed when outbound connections transmit large byte payloads to unapproved cloud storage destinations (e.g. Mega, Dropbox, S3).",
    },
    "T1048.003": {
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Non-C2 Protocol",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "description": "Adversaries may exfiltrate data using an unencrypted network protocol or non-standard port.",
        "detection_context": "Observed when outbound transfers employ FTP, raw TCP, or non-standard ports to unfamiliar external IP addresses.",
    },
    "T1071.004": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to conceal data transfers.",
        "detection_context": "Observed when high-frequency DNS requests or queries with elevated Shannon entropy (>3.8) are detected.",
    },
    "T1083": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Adversaries may enumerate files and directories to locate sensitive intellectual property or credentials.",
        "detection_context": "Observed during rapid filesystem traversal or broad enumeration of restricted directories.",
    },
    "T1020": {
        "technique_id": "T1020",
        "technique_name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1020/",
        "description": "Adversaries may exfiltrate data through automated processing upon reaching specific file criteria or schedules.",
        "detection_context": "Observed when multiple staged files trigger outbound flows in rapid scripted succession.",
    },
    "T1005": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "description": "Adversaries may search local system sources, such as file systems or local databases, to find files of interest.",
        "detection_context": "Observed when restricted and confidential files are accessed or modified outside expected user activity hours.",
    },
}


def get_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve verified technique information from the offline catalog."""
    return MITRE_CATALOG.get(technique_id.strip().upper())


def validate_technique_id(technique_id: str) -> bool:
    """Validate whether an ATT&CK technique ID exists in our approved catalog.

    Used by the output validation layer to reject hallucinated technique identifiers.
    """
    if not technique_id:
        return False
    return technique_id.strip().upper() in MITRE_CATALOG


def list_all_techniques() -> List[Dict[str, Any]]:
    """Return all approved ATT&CK techniques available in SentinelDLP."""
    return list(MITRE_CATALOG.values())


def suggest_techniques_from_evidence(categories: List[str]) -> List[Dict[str, Any]]:
    """Suggest relevant candidate techniques based on verified observation categories."""
    suggestions: List[Dict[str, Any]] = []
    cat_set = {c.upper() for c in categories}

    if "ARCHIVE_EVENT" in cat_set:
        suggestions.append(MITRE_CATALOG["T1560.001"])
    if "FILE_ACTIVITY" in cat_set or "FILE_MODIFIED" in cat_set:
        suggestions.append(MITRE_CATALOG["T1074.001"])
    if "OUTBOUND_TRANSFER" in cat_set or "CLOUD_STORAGE" in cat_set:
        suggestions.append(MITRE_CATALOG["T1567.002"])
    if "DNS_ANOMALY" in cat_set or "DNS_ENTROPY" in cat_set:
        suggestions.append(MITRE_CATALOG["T1071.004"])

    return suggestions
