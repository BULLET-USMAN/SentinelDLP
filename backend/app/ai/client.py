"""AI Client Factory and Observability for SentinelDLP."""

from typing import List
from app.ai.config import ai_config
from app.ai.provider import AIProvider, MockAIProvider, OllamaProvider
from app.ai.schemas import AIStatusResponse, AIModelInfo


def get_ai_provider() -> AIProvider:
    """Instantiate and return the configured AI Provider instance."""
    if ai_config.AI_PROVIDER_TYPE == "ollama":
        return OllamaProvider(
            base_url=ai_config.OLLAMA_BASE_URL,
            model_name=ai_config.OLLAMA_MODEL,
            timeout_seconds=ai_config.AI_TIMEOUT_SECONDS,
        )
    return MockAIProvider(model_id="mock-sentinel-v1")


def get_supported_models_catalog() -> List[AIModelInfo]:
    """Return catalog of approved lightweight models suitable for 6GB VRAM and testing."""
    return [
        AIModelInfo(
            model_id="mock-sentinel-v1",
            provider="mock",
            download_size_approx="0 MB (Zero Download)",
            vram_requirement_approx="0 MB (Zero VRAM)",
            supports_tool_calling=True,
            supports_json_schema=True,
            is_active=ai_config.AI_PROVIDER_TYPE == "mock",
            description="Deterministic local mock provider grounded in actual SentinelDLP database records. Ideal for testing without external model weights.",
        ),
        AIModelInfo(
            model_id="llama3.2:3b",
            provider="ollama",
            download_size_approx="~2.0 GB",
            vram_requirement_approx="~2.5 GB (fits 100% in 6GB RTX 2060)",
            supports_tool_calling=True,
            supports_json_schema=True,
            is_active=ai_config.AI_PROVIDER_TYPE == "ollama" and ai_config.OLLAMA_MODEL == "llama3.2:3b",
            description="Recommended local model: Meta Llama 3.2 3B Instruct (Q4_K_M). High inference speed, native function calling, and structured JSON output.",
        ),
        AIModelInfo(
            model_id="qwen2.5:3b",
            provider="ollama",
            download_size_approx="~1.9 GB",
            vram_requirement_approx="~2.4 GB",
            supports_tool_calling=True,
            supports_json_schema=True,
            is_active=ai_config.AI_PROVIDER_TYPE == "ollama" and ai_config.OLLAMA_MODEL == "qwen2.5:3b",
            description="Alternative local model: Alibaba Qwen 2.5 3B Instruct. Exceptional code and security log reasoning.",
        ),
    ]


async def get_ai_status() -> AIStatusResponse:
    """Retrieve full health and configuration status of the AI subsystem."""
    provider = get_ai_provider()
    health_data = await provider.check_health()

    return AIStatusResponse(
        provider_type=ai_config.AI_PROVIDER_TYPE,
        model_id=health_data.get("model_id", ai_config.OLLAMA_MODEL),
        is_healthy=health_data.get("is_healthy", False),
        details=health_data.get("details", "AI subsystem operational."),
        active_features=[
            "Evidence-Grounded Investigation Reports",
            "Read-Only Server-Controlled Tool Calling",
            "Local MITRE ATT&CK Enterprise Mapping",
            "Anti-Hallucination Record ID Verification",
            "Zero-Leakage Credential Sanitization",
            "Indirect Prompt Injection Guardrails",
        ],
        safety_guardrails=[
            "Immutable read-only tool allowlist (no quarantine, process kill, or blocking)",
            "Max 6 tool calls per investigation bounded limit",
            "No transmission of data to cloud AI services",
            "Deterministic threat risk score preservation",
        ],
        model_storage_location=ai_config.OLLAMA_MODELS_PATH,
        available_models=get_supported_models_catalog(),
    )
