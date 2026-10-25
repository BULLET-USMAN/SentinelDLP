"""Subsystem Coverage Matrix Service for Phase 10 Validation Laboratory."""

from typing import List
from sqlalchemy.orm import Session

from app.models.simulation import SimulationRun
from app.simulation.scenario_registry import get_all_scenarios
from app.simulation.schemas import SubsystemCoverageItem, CoverageLevel


SUBSYSTEM_CAPABILITY_MAP = {
    "SCEN-01": {
        "SCANNER": (CoverageLevel.SUPPORTED, ["SAFE_HASH_INSPECTION"], "Benign file classification with zero false alerts."),
        "MONITORING": (CoverageLevel.SUPPORTED, ["FILE_EVENT_NORMALIZATION"], "Standard create and modify events recorded."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["BENIGN_BASELINE"], "Zero alerts generated for benign activity."),
    },
    "SCEN-02": {
        "SCANNER": (CoverageLevel.SUPPORTED, ["RULE-PII-CNIC-PK", "RULE-FIN-PAYMENT-CARD", "RULE-CRED-API-TOKEN"], "Extracts and detects synthetic PII and secrets."),
        "CLASSIFICATION": (CoverageLevel.SUPPORTED, ["SENSITIVITY_SCORING"], "Correctly flags files as CONFIDENTIAL and RESTRICTED."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["SENSITIVE_INVENTORY"], "Enriches file inventory with privacy metadata."),
    },
    "SCEN-03": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["RAPID_EVENT_BURST"], "Tracks consecutive modifications on sensitive targets."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["RULE-SENS-MOD", "RULE-RAPID-MOD"], "Escalates threat score on burst modification."),
    },
    "SCEN-04": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["BULK_RENAME_STREAM"], "Identifies extension tampering and rapid rename operations."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["RULE-BULK-RENAME", "RULE-EXT-CHANGE"], "Generates alert for ransomware-like renaming heuristics."),
    },
    "SCEN-05": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["ARCHIVE_FILE_IDENTIFICATION"], "Detects archive creation without claiming plaintext certainty."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["STAGING_RISK_SCORING"], "Elevates staging risk indicator."),
        "EXFILTRATION": (CoverageLevel.SUPPORTED, ["EXFIL-002"], "Triggers staging correlation rule."),
    },
    "SCEN-06": {
        "NETWORK": (CoverageLevel.SUPPORTED, ["NET-001", "NET-003", "NET-005"], "Detects flow spikes, multi-port probes, and DNS entropy."),
    },
    "SCEN-07": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["SENSITIVE_EDIT_EVENT"], "Feeds sensitive file telemetry."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["COMPOSITE_RISK"], "Prepares multi-evidence assessment."),
        "EXFILTRATION": (CoverageLevel.SUPPORTED, ["EXFIL-003", "EXFIL-007"], "Correlates file + archive + outbound transfer flow."),
        "NETWORK": (CoverageLevel.SUPPORTED, ["TRANSFER_TELEMETRY"], "Provides outbound byte count and external host evidence."),
    },
    "SCEN-08": {
        "NETWORK": (CoverageLevel.SUPPORTED, ["ISOLATED_TELEMETRY"], "Processes network events for distinct endpoints."),
        "EXFILTRATION": (CoverageLevel.SUPPORTED, ["CORRELATION_ISOLATION"], "Negative control: asserts zero cross-endpoint false correlation."),
    },
    "SCEN-09": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["RULE-COVERAGE-WARN"], "Identifies unmonitored filepaths and sensor degradation."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["CONFIDENCE_DOWNGRADE"], "Penalizes evidence confidence when telemetry is degraded."),
        "NETWORK": (CoverageLevel.SUPPORTED, ["NET-009"], "Identifies inactive network sensor intervals."),
    },
    "SCEN-10": {
        "MONITORING": (CoverageLevel.SUPPORTED, ["STREAM_DEDUPLICATION"], "Processes duplicate and chronological out-of-order events."),
        "RISK_ENGINE": (CoverageLevel.SUPPORTED, ["RULE-REPEAT-CHANGE"], "Increments alert repeat count instead of alert spam."),
    },
    "SCEN-11": {
        "AI_ANALYST": (CoverageLevel.SUPPORTED, ["AI-VERIFIED-REPORT", "PROMPT-INJECTION-NEUTRALIZED"], "Generates grounded investigation reports and sanitizes adversarial prompts."),
    },
}


class CoverageService:
    """Builds matrix of subsystem test coverage across all scenarios."""

    @staticmethod
    def get_coverage_matrix(db: Session) -> List[SubsystemCoverageItem]:
        """Return the detailed coverage breakdown for all scenarios and subsystems."""
        items: List[SubsystemCoverageItem] = []
        scenarios = get_all_scenarios()

        for scen in scenarios:
            mapping = SUBSYSTEM_CAPABILITY_MAP.get(scen.scenario_id, {})
            for subsys, (level, rules, notes) in mapping.items():
                items.append(
                    SubsystemCoverageItem(
                        subsystem=subsys,
                        scenario_id=scen.scenario_id,
                        scenario_name=scen.name,
                        coverage_level=level,
                        rules_evaluated=rules,
                        notes=notes,
                    )
                )
        return items
