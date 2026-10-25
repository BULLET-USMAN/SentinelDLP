"""Configuration module for SentinelDLP Phase 9 AI-Powered SOC Analyst."""

import os
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIConfig(BaseSettings):
    """Configuration for AI SOC Analyst, Ollama integration, and security guardrails."""

    # Provider selection: 'mock' for deterministic local mock or 'ollama' for real local LLM
    AI_PROVIDER_TYPE: Literal["mock", "ollama"] = Field(
        default="mock",
        description="Active AI Provider: 'mock' for deterministic testing or 'ollama' for local inference",
    )

    # Local Ollama Inference Configuration
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434",
        description="HTTP URL for local Ollama daemon (use http://host.docker.internal:11434 inside container)",
    )
    OLLAMA_MODEL: str = Field(
        default="llama3.2:3b",
        description="Target Ollama model identifier (e.g., llama3.2:3b, qwen2.5:3b)",
    )
    OLLAMA_MODELS_PATH: str = Field(
        default="E:\\OllamaModels",
        description="Safe non-system storage directory for downloaded local weights",
    )

    # Performance, Timeout & Safety Limits
    AI_TIMEOUT_SECONDS: int = Field(
        default=30,
        description="Maximum request timeout for model generation",
    )
    MAX_TOOL_CALLS_PER_INVESTIGATION: int = Field(
        default=6,
        description="Strict bound on read-only tool calls executed per investigation",
    )
    MAX_CONVERSATION_HISTORY_MESSAGES: int = Field(
        default=20,
        description="Sliding window message capacity per conversation session",
    )

    # Hard Security Boundaries
    ALLOW_DISRUPTIVE_ACTIONS: bool = Field(
        default=False,
        description="Immutable flag enforcing read-only operations. Must NEVER be set to True.",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


ai_config = AIConfig()
