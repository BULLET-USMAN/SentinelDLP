"""Investigation and reporting prompt builders for SentinelDLP AI subsystem."""

import json
from typing import Dict, Any


def build_investigation_analysis_prompt(context: Dict[str, Any], analyst_query: str = "") -> str:
    """Format sanitized evidence context into a structured prompt."""
    query_section = f"\nANALYST HYPOTHESIS / QUERY: {analyst_query}\n" if analyst_query else ""
    return f"""INVESTIGATION CONTEXT:
{json.dumps(context, indent=2, default=str)}
{query_section}
TASK:
Analyze the verified evidence above. Differentiate observed facts from unverified inferences.
Map supported findings to valid MITRE ATT&CK techniques from the local catalog.
Identify missing evidence required to confirm or reject malicious exfiltration.
Output your findings as structured JSON conforming to the SentinelDLP investigation report schema.
"""
