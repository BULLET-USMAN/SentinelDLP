"""Tool Registry and JSON Schemas for AI SOC Analyst."""

from typing import Dict, List, Any, Callable, Optional
from app.ai.tools import alerts, files, events, investigations, network
from app.ai.mitre import catalog

# Function definition schemas formatted for Ollama / OpenAI tool calling
TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_alert",
            "description": "Retrieve security alert metadata, threat score, severity, and rule details by alert_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The unique UUID of the security alert to inspect.",
                    }
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_risk_assessment",
            "description": "Retrieve detailed threat score calculation breakdown and contributing rule matches.",
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {
                        "type": "string",
                        "description": "The UUID of the risk assessment.",
                    }
                },
                "required": ["assessment_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_classification",
            "description": "Retrieve sensitivity tier (RESTRICTED, CONFIDENTIAL, etc.) and findings for a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_id": {
                        "type": "string",
                        "description": "The UUID of the scanned file.",
                    }
                },
                "required": ["file_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_activity",
            "description": "Retrieve normalized filesystem watchdog activity event details by event_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "The UUID of the file activity event.",
                    }
                },
                "required": ["event_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_investigation_timeline",
            "description": "Retrieve the multi-stage forensic event timeline synthesized for an exfiltration case.",
            "parameters": {
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "The UUID of the exfiltration investigation.",
                    }
                },
                "required": ["investigation_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_exfiltration_evidence",
            "description": "Retrieve exfiltration case details, risk score, and triggered correlation rules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "The UUID of the exfiltration investigation.",
                    }
                },
                "required": ["investigation_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_events",
            "description": "Retrieve recent network connection flows, DNS queries, and IDS signatures.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of network events to retrieve (1-30).",
                        "default": 15,
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_sensor_status",
            "description": "Retrieve operational and health status of a network monitoring sensor.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sensor_id": {
                        "type": "string",
                        "description": "The identifier of the sensor (e.g., zeek_sensor_01, suricata_ids_01).",
                    }
                },
                "required": ["sensor_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_mitre_technique",
            "description": "Retrieve validated information from the offline MITRE ATT&CK catalog by technique_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "The MITRE ATT&CK ID (e.g. T1074.001, T1560.001, T1567.002).",
                    }
                },
                "required": ["technique_id"],
            },
        },
    },
]


def get_tool_handler(tool_name: str) -> Optional[Callable]:
    """Resolve a tool name to its backend implementation function."""
    handlers: Dict[str, Callable] = {
        "get_alert": alerts.get_alert,
        "get_risk_assessment": alerts.get_risk_assessment,
        "get_file_classification": files.get_file_classification,
        "get_file_activity": events.get_file_activity,
        "get_investigation_timeline": investigations.get_investigation_timeline,
        "get_exfiltration_evidence": investigations.get_exfiltration_evidence,
        "get_network_events": network.get_network_events,
        "get_sensor_status": network.get_sensor_status,
        "get_mitre_technique": lambda db, technique_id: catalog.get_technique(technique_id),
    }
    return handlers.get(tool_name)
