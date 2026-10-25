"""Data Sanitization and Prompt Injection Defense for SentinelDLP AI Subsystem.

Ensures zero confidential values (credentials, card numbers, API keys) ever enter
model context, and insulates prompts against indirect prompt injection embedded in
log metadata, filenames, and network hosts.
"""

import re
from typing import Any, Dict, List, Union


# Regex patterns for stripping/redacting credentials and sensitive values
REDACTION_PATTERNS = [
    # API Keys & Tokens
    (r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED_AWS_KEY]"),
    (r"ghp_[0-9a-zA-Z]{36}", "ghp_[REDACTED_GITHUB_PAT]"),
    (r"glpat-[0-9a-zA-Z\-_]{20,}", "glpat-[REDACTED_GITLAB_PAT]"),
    (r"bearer\s+[a-zA-Z0-9_\-\.]{24,}", "Bearer [REDACTED_TOKEN]", re.IGNORECASE),
    # Private Keys
    (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    # Credit Card numbers (13-19 digits with separators)
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_PAYMENT_CARD]"),
    # US SSN (XXX-XX-XXXX)
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    # Common password patterns in logs
    (r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", "password=[REDACTED_PASSWORD]", re.IGNORECASE),
]

# Patterns characteristic of indirect prompt injection attempts
INJECTION_SIGNATURES = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:the\s+)?above",
    r"you\s+are\s+now\s+(?:a|an)\s+",
    r"system\s*:\s*override",
    r"reveal\s+(?:all\s+)?(?:database|system|api)\s+keys",
    r"sudo\s+",
    r"drop\s+table",
    r"delete\s+from",
]


def sanitize_text(text: str, max_chars: int = 1500) -> str:
    """Sanitize raw text strings before injecting into LLM context."""
    if not text:
        return ""

    sanitized = text
    for item in REDACTION_PATTERNS:
        if len(item) == 3:
            pattern, replacement, flags = item
            sanitized = re.sub(pattern, replacement, sanitized, flags=flags)
        else:
            pattern, replacement = item
            sanitized = re.sub(pattern, replacement, sanitized)

    # Truncate to bound token usage
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "... [truncated]"

    return sanitized


def wrap_untrusted_telemetry(label: str, content: Union[str, Dict, List]) -> str:
    """Enclose untrusted external data (filenames, logs, network hosts) in defensive tags.

    Teaches the LLM to process the content strictly as telemetry, not as instructions.
    """
    raw_str = str(content)
    # Check for prompt injection signatures to flag in metadata
    has_injection = any(re.search(sig, raw_str, re.IGNORECASE) for sig in INJECTION_SIGNATURES)

    clean_content = sanitize_text(raw_str)
    injection_notice = ' injection_flag="SUSPICIOUS_PROMPT_INJECTION_DETECTED"' if has_injection else ""

    return (
        f'<{label} type="untrusted_telemetry"{injection_notice}>\n'
        f"{clean_content}\n"
        f"</{label}>"
    )


def sanitize_evidence_dict(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize dictionary data structures before context assembly."""
    sanitized: Dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_text(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_evidence_dict(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_evidence_dict(item) if isinstance(item, dict)
                else sanitize_text(str(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized
