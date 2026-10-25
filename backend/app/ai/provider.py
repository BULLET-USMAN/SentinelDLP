"""AI Provider Interface, Local Ollama Implementation, and Deterministic Mock Provider.

Implements:
- AIProvider Protocol: Standardized interface for model generation & tool calling.
- MockAIProvider: Scenario-aware, deterministic local provider for offline execution and testing.
- OllamaProvider: Production-ready HTTP integration for local Ollama inference daemons.
"""

import json
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import httpx

from app.ai.config import ai_config
from app.ai.mitre.catalog import MITRE_CATALOG


class AIProvider(ABC):
    """Abstract Base Class for SentinelDLP AI Providers."""

    @abstractmethod
    async def check_health(self) -> Dict[str, Any]:
        """Verify availability and readiness of the underlying model inference service."""
        pass

    @abstractmethod
    async def generate_chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate interactive chat response with optional tool calling support."""
        pass

    @abstractmethod
    async def generate_investigation_report(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate structured investigation report matching SentinelDLP schema."""
        pass


class MockAIProvider(AIProvider):
    """Deterministic, scenario-aware Mock AI Provider.

    Operates completely locally with zero network calls, zero model downloads,
    and zero VRAM impact, providing grounded security analysis based on actual evidence.
    """

    def __init__(self, model_id: str = "mock-sentinel-v1"):
        self.model_id = model_id
        self.provider_type = "mock"

    async def check_health(self) -> Dict[str, Any]:
        return {
            "provider_type": self.provider_type,
            "model_id": self.model_id,
            "is_healthy": True,
            "details": "Deterministic Mock AI Provider active. Ready for local security analysis and testing without external model weights.",
            "mode": "MOCK_DETERMINISTIC",
        }

    async def generate_chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        last_message = messages[-1]["content"] if messages else ""
        lower_msg = last_message.lower()

        # Check for prompt injection simulation
        if "ignore previous instructions" in lower_msg or "reveal all" in lower_msg:
            return {
                "role": "assistant",
                "content": (
                    "Security Notice: The input contains text matching indirect prompt injection signatures. "
                    "In accordance with SentinelDLP security guardrails, instructions embedded within untrusted "
                    "log data or analyst inputs cannot modify system boundaries, bypass read-only tool limits, "
                    "or disclose sensitive internal credentials."
                ),
                "evidence_references": [],
                "tool_invocations": [],
            }

        # Context-aware responses
        if "false positive" in lower_msg:
            content = (
                "Regarding false positive potential: Normal developer workflows, automated backup scripts, "
                "or system maintenance tasks frequently create archives or bulk-modify files in authorized directories. "
                "In SentinelDLP, file sensitivity alone is never treated as proof of malicious exfiltration. "
                "To distinguish a legitimate administrative archive from unauthorized staging, verify whether "
                "an unapproved outbound network transfer occurred within the 15-minute correlation window."
            )
        elif "risk score" in lower_msg or "score" in lower_msg:
            content = (
                "SentinelDLP calculates threat scores deterministically between 0 and 100 based on primary rule "
                "contributions and diminishing secondary rule weights. For example, sensitive file deletion or bulk renaming "
                "contributes to score elevation, while routine modifications remain in the LOW band (0-29). "
                "As an AI assistant, I provide qualitative context and evidence interpretation; I do not override "
                "or alter the deterministic numerical score."
            )
        elif "network" in lower_msg or "transfer" in lower_msg:
            content = (
                "Available network telemetry is ingested from offline Zeek connection logs, Suricata EVE records, "
                "and PCAP parsers. Transfer evidence is explicitly attributed with IMPORTED or LAB_SIMULATED provenance "
                "and tagged as 'circumstantial' relationship evidence, because encrypted application flows cannot be "
                "definitively proven from packet headers alone."
            )
        else:
            content = (
                f"SentinelDLP AI SOC Analyst standing by. I have analyzed your inquiry regarding security telemetry. "
                f"All observations are cross-referenced with authorized database records across file activity, sensitive "
                f"classifications, threat scoring, and network flows. How can I assist your investigation further?"
            )

        return {
            "role": "assistant",
            "content": content,
            "evidence_references": [],
            "tool_invocations": [],
        }

    async def generate_investigation_report(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        investigation_id = context.get("investigation_id", "inv-default")
        title = context.get("title", "Security Investigation")
        risk_score = context.get("risk_score", 50)
        rules_triggered = context.get("rules_triggered", [])
        evidence_links = context.get("evidence_links", [])

        # Collect verified record IDs from context
        available_ids = set(context.get("available_record_ids", []))
        for el in evidence_links:
            if isinstance(el, dict) and el.get("evidence_id"):
                available_ids.add(el["evidence_id"])

        # Determine scenario based on risk score and rules
        is_exfiltration = risk_score >= 70 or any("EXFIL" in str(r) for r in rules_triggered)
        is_suspicious_activity = risk_score >= 40 and not is_exfiltration

        observed_facts = []
        mitre_mappings = []
        possible_explanations = []
        missing_evidence = []
        recommended_actions = []

        if is_exfiltration:
            executive_summary = (
                f"Correlated investigation '{title}' indicates high-risk multi-stage activity. "
                f"Telemetry reveals sensitive data access temporally aligned with archive creation "
                f"and potential outbound transfer flow (Calculated Threat Score: {risk_score}/100)."
            )
            assessment = (
                "Evidence indicates potential data staging and exfiltration behavior. "
                "However, in accordance with defensive causal modesty, network transfer records are marked "
                "as circumstantial evidence unless explicit content inspection confirms payload contents."
            )
            confidence_assessment = "PARTIAL_SUPPORT"
            evidence_completeness = "PARTIAL"

            # Observed facts
            for r_id in list(available_ids)[:3]:
                observed_facts.append({
                    "fact": f"Correlated security event recorded in timeline under record {r_id}",
                    "record_id": r_id,
                    "source_technology": "correlation_engine",
                    "provenance": "OBSERVED",
                })

            possible_explanations = [
                "Unauthorized insider staging sensitive files into an archive for egress.",
                "Authorized administrative maintenance or automated backup workflow.",
                "Testing or developer build script compressing local assets.",
            ]
            missing_evidence = [
                "Process-to-user attribution (Windows process token or host user identity).",
                "Decrypted application payload of outbound transfer to confirm archive presence.",
            ]
            recommended_actions = [
                "Interview the assigned endpoint custodian regarding archive operations.",
                "Inspect host event logs for execution of zip/tar utilities.",
                "Verify whether destination IP/domain is an approved corporate storage endpoint.",
            ]
            mitre_mappings = [
                {
                    "technique_id": "T1074.001",
                    "technique_name": MITRE_CATALOG["T1074.001"]["technique_name"],
                    "tactic": "Collection",
                    "justification": "Sensitive files aggregated into staging directory within evaluation window.",
                    "confidence": "PARTIAL_SUPPORT",
                },
                {
                    "technique_id": "T1560.001",
                    "technique_name": MITRE_CATALOG["T1560.001"]["technique_name"],
                    "tactic": "Collection",
                    "justification": "Archive creation observed in temporal proximity to sensitive file access.",
                    "confidence": "PARTIAL_SUPPORT",
                },
                {
                    "technique_id": "T1567.002",
                    "technique_name": MITRE_CATALOG["T1567.002"]["technique_name"],
                    "tactic": "Exfiltration",
                    "justification": "Outbound data flow directed to cloud or external destination.",
                    "confidence": "LIMITED_SUPPORT",
                },
            ]
        elif is_suspicious_activity:
            executive_summary = (
                f"Investigation '{title}' documents unusual filesystem modification velocity. "
                f"Sensitive assets were altered in authorized directories (Threat Score: {risk_score}/100)."
            )
            assessment = (
                "File modifications exceed normal baseline velocity, but no archive creation "
                "or outbound egress flows were observed. Low likelihood of immediate exfiltration."
            )
            confidence_assessment = "PARTIAL_SUPPORT"
            evidence_completeness = "PARTIAL"
            possible_explanations = [
                "Bulk search-and-replace or refactoring in source code repository.",
                "Batch update performed by an authorized internal application.",
            ]
            missing_evidence = [
                "Outbound network flow or transfer evidence (none detected in window).",
                "Archive utility execution logs.",
            ]
            recommended_actions = [
                "Review recent git commits or application change tickets matching modified files.",
                "Confirm that modified documents maintain expected sensitivity classifications.",
            ]
            mitre_mappings = [
                {
                    "technique_id": "T1074.001",
                    "technique_name": MITRE_CATALOG["T1074.001"]["technique_name"],
                    "tactic": "Collection",
                    "justification": "Multiple sensitive files modified in rapid succession.",
                    "confidence": "LIMITED_SUPPORT",
                }
            ]
        else:
            executive_summary = (
                f"Routine activity recorded for investigation '{title}'. "
                f"Telemetry reflects isolated or low-risk file access (Threat Score: {risk_score}/100)."
            )
            assessment = (
                "Activity is consistent with ordinary day-to-day operations. "
                "No indicators of compromise, lateral movement, or data staging observed."
            )
            confidence_assessment = "STRONG_SUPPORT"
            evidence_completeness = "COMPLETE"
            possible_explanations = [
                "Standard user document editing in authorized folder.",
            ]
            missing_evidence = [
                "No adverse telemetry or security anomalies identified.",
            ]
            recommended_actions = [
                "Close alert as normal operational activity if confirmed by user.",
            ]

        return {
            "model_id": self.model_id,
            "provider_type": self.provider_type,
            "status": "COMPLETED",
            "executive_summary": executive_summary,
            "assessment": assessment,
            "confidence_assessment": confidence_assessment,
            "evidence_completeness": evidence_completeness,
            "observed_facts": observed_facts,
            "possible_explanations": possible_explanations,
            "missing_evidence": missing_evidence,
            "recommended_actions": recommended_actions,
            "mitre_attack_mappings": mitre_mappings,
            "evidence_references": list(available_ids)[:5],
            "tool_calls_count": len(observed_facts),
        }


class OllamaProvider(AIProvider):
    """Production integration for local Ollama inference service.

    Connects to the local Ollama HTTP REST API, handles tool calling,
    enforces request timeouts, and structures model responses.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ):
        self.base_url = (base_url or ai_config.OLLAMA_BASE_URL).rstrip("/")
        self.model_name = model_name or ai_config.OLLAMA_MODEL
        self.timeout = timeout_seconds or ai_config.AI_TIMEOUT_SECONDS
        self.provider_type = "ollama"

    async def check_health(self) -> Dict[str, Any]:
        """Query local Ollama /api/version and /api/tags to verify model readiness."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get(f"{self.base_url}/api/version")
                if res.status_code == 200:
                    version_data = res.json()
                    # Check available models
                    models_res = await client.get(f"{self.base_url}/api/tags")
                    models_data = models_res.json() if models_res.status_code == 200 else {}
                    installed_models = [m.get("name") for m in models_data.get("models", [])]
                    model_ready = any(self.model_name in m for m in installed_models)

                    return {
                        "provider_type": self.provider_type,
                        "model_id": self.model_name,
                        "is_healthy": model_ready,
                        "details": f"Ollama daemon v{version_data.get('version')} active at {self.base_url}. Model '{self.model_name}' installed: {model_ready}.",
                        "installed_models": installed_models,
                        "mode": "OLLAMA_LOCAL_DAEMON",
                    }
                return {
                    "provider_type": self.provider_type,
                    "model_id": self.model_name,
                    "is_healthy": False,
                    "details": f"Ollama daemon responded with status code {res.status_code}.",
                    "mode": "OLLAMA_LOCAL_DAEMON",
                }
        except httpx.ConnectError:
            return {
                "provider_type": self.provider_type,
                "model_id": self.model_name,
                "is_healthy": False,
                "details": f"Cannot connect to Ollama daemon at {self.base_url}. Service is currently offline.",
                "mode": "OLLAMA_LOCAL_DAEMON",
            }
        except Exception as exc:
            return {
                "provider_type": self.provider_type,
                "model_id": self.model_name,
                "is_healthy": False,
                "details": f"Ollama health check error: {str(exc)}",
                "mode": "OLLAMA_LOCAL_DAEMON",
            }

    async def generate_chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
            res = await client.post(f"{self.base_url}/api/chat", json=payload)
            if res.status_code != 200:
                raise RuntimeError(f"Ollama chat error ({res.status_code}): {res.text}")

            result = res.json()
            message = result.get("message", {})
            return {
                "role": message.get("role", "assistant"),
                "content": message.get("content", ""),
                "tool_calls": message.get("tool_calls", []),
                "evidence_references": [],
            }

    async def generate_investigation_report(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = (
            "You are a defensive cybersecurity SOC Analyst. Analyze the following verified security evidence "
            "and generate a structured JSON investigation report strictly complying with the schema.\n\n"
            f"EVIDENCE CONTEXT:\n{json.dumps(context, indent=2, default=str)}"
        )

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
        }

        async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
            res = await client.post(f"{self.base_url}/api/generate", json=payload)
            if res.status_code != 200:
                raise RuntimeError(f"Ollama generation error ({res.status_code}): {res.text}")

            result = res.json()
            raw_text = result.get("response", "{}")
            try:
                report_dict = json.loads(raw_text)
            except json.JSONDecodeError:
                report_dict = {"assessment": raw_text, "executive_summary": "Generated assessment."}

            report_dict["model_id"] = self.model_name
            report_dict["provider_type"] = self.provider_type
            report_dict["status"] = "COMPLETED"
            return report_dict
