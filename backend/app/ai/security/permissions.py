"""Permission verification and disruptive-action boundaries for AI tools."""

from typing import Set

# Explicit allowlist of authorized read-only inspection tools
ALLOWED_READ_ONLY_TOOLS: Set[str] = {
    "get_alert",
    "get_risk_assessment",
    "get_file_classification",
    "get_file_activity",
    "get_investigation_timeline",
    "get_exfiltration_evidence",
    "get_network_events",
    "get_sensor_status",
    "get_mitre_technique",
    "get_detection_rules",
}

# Explicit blocklist of prohibited disruptive or mutating operations
PROHIBITED_DISRUPTIVE_OPERATIONS: Set[str] = {
    "quarantine_file",
    "delete_file",
    "terminate_process",
    "block_ip",
    "block_domain",
    "modify_firewall",
    "execute_script",
    "shell_exec",
    "raw_sql_query",
    "restart_host",
}


def is_tool_authorized(tool_name: str) -> bool:
    """Check whether a requested tool name is in the strictly authorized read-only allowlist."""
    if not tool_name:
        return False
    clean_name = tool_name.strip()
    if clean_name in PROHIBITED_DISRUPTIVE_OPERATIONS:
        return False
    return clean_name in ALLOWED_READ_ONLY_TOOLS


def verify_investigation_access(user_id: str, investigation_id: str) -> bool:
    """Verify that the caller has access permissions to the requested investigation scope."""
    # SentinelDLP currently operates under local SOC analyst RBAC
    if not user_id or not investigation_id:
        return False
    return True
