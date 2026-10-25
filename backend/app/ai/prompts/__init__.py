"""Prompts package for SentinelDLP AI subsystem."""

from app.ai.prompts.system_prompt import AI_SOC_SYSTEM_PROMPT
from app.ai.prompts.investigation_prompt import build_investigation_analysis_prompt

__all__ = [
    "AI_SOC_SYSTEM_PROMPT",
    "build_investigation_analysis_prompt",
]
