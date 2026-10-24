"""Risk Scoring and Assessment Calculator for SentinelDLP (Phase 5).

Calculates deterministic normalized 0–100 threat scores, determines severity bands,
and generates structured explainability and SOC analyst recommendations.
"""

from dataclasses import dataclass
from typing import List, Tuple
from app.models.monitoring import FileActivityEvent
from app.risk.rules.base import RuleEvaluationResult
from app.risk.severity import RiskSeverity, score_to_severity


@dataclass
class CalculatedScore:
    """Contains calculated numerical score and explainable assessment metadata."""

    risk_score: int
    severity: RiskSeverity
    assessment_status: str
    explanation: str
    limitations: str
    recommended_action: str


def calculate_risk_score(
    event: FileActivityEvent,
    matches: List[RuleEvaluationResult],
) -> CalculatedScore:
    """Calculate deterministic 0–100 threat score from rule matches with diminishing returns."""
    if not matches:
        return CalculatedScore(
            risk_score=0,
            severity=RiskSeverity.LOW,
            assessment_status="assessed",
            explanation=f"Standard activity observed for '{event.relative_path}'. All metrics remain within baseline parameters.",
            limitations=(
                "Filesystem notifications observe local operations; they do not confirm process "
                "attribution, memory access, or network activity."
            ),
            recommended_action="No analyst intervention required. Routine monitoring active.",
        )

    # Check for coverage warnings
    only_coverage_warnings = all(m.is_coverage_warning for m in matches)
    if only_coverage_warnings:
        points = sum(m.score_contribution for m in matches)
        score = min(29, points)  # Coverage warning alone stays in LOW severity band
        return CalculatedScore(
            risk_score=score,
            severity=RiskSeverity.LOW,
            assessment_status="warning",
            explanation=f"Telemetry coverage warning: {'; '.join(m.explanation for m in matches)}",
            limitations="Telemetry coverage warning indicates potential visibility degradation.",
            recommended_action="Inspect agent health, host buffer settings, and queue saturation metrics.",
        )

    # Threat rule scoring: highest rule provides primary weight, others add diminishing contributions
    sorted_matches = sorted(matches, key=lambda m: m.score_contribution, reverse=True)
    primary = sorted_matches[0].score_contribution
    secondary_sum = sum(m.score_contribution * 0.6 for m in sorted_matches[1:])
    raw_score = primary + secondary_sum
    score = min(100, max(0, int(round(raw_score))))
    severity = score_to_severity(score)

    # Build explainable narrative
    explanation_parts = [m.explanation for m in sorted_matches]
    explanation = " | ".join(explanation_parts)

    # Standard limitations disclaimer
    limitations = (
        "Filesystem notifications observe file creation, modification, and movement; "
        "they do NOT confirm file reads, memory scraping, or external network exfiltration."
    )

    # Actionable guidance based on severity
    if severity == RiskSeverity.CRITICAL:
        recommended_action = (
            "CRITICAL: Immediate analyst triage recommended. Review affected file paths, check host "
            "event logs for active processes, and verify recent authorized user operations."
        )
    elif severity == RiskSeverity.HIGH:
        recommended_action = (
            "HIGH: Elevated risk signals detected. Inspect the modified file paths, verify if bulk "
            "or automated transformation was authorized, and examine directory integrity."
        )
    elif severity == RiskSeverity.MEDIUM:
        recommended_action = (
            "MEDIUM: Unusually clustered or sensitive activity observed. Monitor directory trends "
            "and verify asset access authorization if unexpected."
        )
    else:
        recommended_action = "LOW: Low-priority security event. Logged for longitudinal baseline analysis."

    return CalculatedScore(
        risk_score=score,
        severity=severity,
        assessment_status="assessed",
        explanation=explanation,
        limitations=limitations,
        recommended_action=recommended_action,
    )
