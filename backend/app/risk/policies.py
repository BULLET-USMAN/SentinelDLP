"""Risk Scoring Policy and Threshold Configurations for SentinelDLP (Phase 5).

Provides deterministic, versioned, configurable scoring parameters, weights,
and alert generation thresholds.
"""

from typing import Any, Dict


POLICY_VERSION = "1.0.0"


DEFAULT_SCORING_POLICY: Dict[str, Any] = {
    "policy_version": POLICY_VERSION,
    "severity_thresholds": {
        "LOW": [0, 29],
        "MEDIUM": [30, 59],
        "HIGH": [60, 79],
        "CRITICAL": [80, 100],
    },
    "alerting": {
        "min_alert_score": 30,          # Any assessment with score >= 30 triggers an alert
        "suppression_window_seconds": 300,  # 5-minute sliding window for duplicate alert suppression
        "auto_alert_rules": [           # Priority rules that always warrant an alert regardless of base score
            "RULE-BULK-RENAME",
            "RULE-SENS-DEL",
            "RULE-RAPID-MOD",
        ],
    },
    "rules": {
        "RULE-SENS-MOD": {
            "enabled": True,
            "version": "1.0.0",
            "weights": {
                "RESTRICTED": 25,
                "CONFIDENTIAL": 15,
                "INTERNAL": 5,
                "PUBLIC": 0,
            },
        },
        "RULE-RAPID-MOD": {
            "enabled": True,
            "version": "1.0.0",
            "window_minutes": 5,
            "threshold_files": 5,
            "high_threshold_files": 15,
            "base_points": 25,
            "high_points": 40,
        },
        "RULE-BULK-RENAME": {
            "enabled": True,
            "version": "1.0.0",
            "window_minutes": 5,
            "threshold_renames": 5,
            "high_threshold_renames": 12,
            "base_points": 30,
            "high_points": 45,
        },
        "RULE-SENS-DEL": {
            "enabled": True,
            "version": "1.0.0",
            "window_minutes": 15,
            "threshold_deletions": 2,
            "high_threshold_deletions": 5,
            "base_points": 35,
            "high_points": 50,
        },
        "RULE-REPEAT-CHANGE": {
            "enabled": True,
            "version": "1.0.0",
            "window_minutes": 5,
            "threshold_changes_single_file": 4,
            "base_points": 20,
            "high_points": 30,
        },
        "RULE-SENS-VOLUME": {
            "enabled": True,
            "version": "1.0.0",
            "window_minutes": 15,
            "threshold_sensitive_events": 5,
            "high_threshold_sensitive_events": 10,
            "base_points": 30,
            "high_points": 45,
        },
        "RULE-EXT-CHANGE": {
            "enabled": True,
            "version": "1.0.0",
            "base_points": 20,
            "sensitive_multiplier": 1.5,
            "suspicious_extensions": [
                ".locked", ".crypto", ".enc", ".crypted", ".dark",
                ".crypt", ".wnry", ".aes", ".ransom"
            ],
            "suspicious_extension_bonus": 25,
        },
        "RULE-COVERAGE-WARN": {
            "enabled": True,
            "version": "1.0.0",
            "base_points": 10,
            "is_coverage_warning": True,
        },
    },
}
