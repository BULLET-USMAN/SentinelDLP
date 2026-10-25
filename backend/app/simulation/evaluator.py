"""Detection validation evaluator for Phase 10 Simulation Laboratory.

Compares observed detections, alerts, and investigations against ground truth
expectations and computes statistical accuracy metrics (TP, FP, TN, FN,
Precision, Recall, F1, and False Positive Rate).
"""

from typing import List, Dict, Any, Tuple
from app.simulation.schemas import ScenarioDefinition


class EvaluationResult:
    """Holds computed evaluation metrics and pass/fail determination."""

    def __init__(
        self,
        pass_status: str,
        expected_events_count: int,
        actual_events_count: int,
        expected_rules: List[str],
        actual_rules: List[str],
        matched_rules: List[str],
        unmatched_rules: List[str],
        unexpected_rules: List[str],
        expected_alerts_count: int,
        actual_alerts_count: int,
        expected_investigations_count: int,
        actual_investigations_count: int,
        precision: float,
        recall: float,
        f1_score: float,
        false_positive_rate: float,
        latency_ms: float,
        failure_reasons: List[str],
    ):
        self.pass_status = pass_status
        self.expected_events_count = expected_events_count
        self.actual_events_count = actual_events_count
        self.expected_rules = expected_rules
        self.actual_rules = actual_rules
        self.matched_rules = matched_rules
        self.unmatched_rules = unmatched_rules
        self.unexpected_rules = unexpected_rules
        self.expected_alerts_count = expected_alerts_count
        self.actual_alerts_count = actual_alerts_count
        self.expected_investigations_count = expected_investigations_count
        self.actual_investigations_count = actual_investigations_count
        self.precision = precision
        self.recall = recall
        self.f1_score = f1_score
        self.false_positive_rate = false_positive_rate
        self.latency_ms = latency_ms
        self.failure_reasons = failure_reasons


def evaluate_scenario_run(
    scenario: ScenarioDefinition,
    observed_events_count: int,
    observed_rules: List[str],
    observed_alerts_count: int,
    observed_investigations_count: int,
    latency_ms: float,
    execution_errors: List[str],
) -> EvaluationResult:
    """Evaluate observed security results against scenario expectations."""
    expected_rules_set = set(scenario.expected_rules)
    actual_rules_set = set(observed_rules)

    # Normalize rule matching (support prefix matching e.g. "NET-001" in "NET-001: Outbound Volume")
    matched: List[str] = []
    unmatched: List[str] = []
    
    for exp in scenario.expected_rules:
        found = False
        for act in observed_rules:
            if exp in act or act in exp:
                found = True
                matched.append(exp)
                break
        if not found:
            unmatched.append(exp)

    unexpected: List[str] = []
    for act in observed_rules:
        found = False
        for exp in scenario.expected_rules:
            if exp in act or act in exp:
                found = True
                break
        if not found:
            unexpected.append(act)

    failure_reasons: List[str] = list(execution_errors)

    # Negative control scenario evaluation (expected 0 alerts, 0 investigations, 0 rules)
    if scenario.negative_control or (len(scenario.expected_rules) == 0 and scenario.expected_alerts == 0):
        if observed_alerts_count == 0 and observed_investigations_count == 0 and len(observed_rules) == 0:
            pass_status = "PASSED"
            precision = 1.0
            recall = 1.0
            f1 = 1.0
            fpr = 0.0
        else:
            pass_status = "FAILED"
            precision = 0.0
            recall = 0.0
            f1 = 0.0
            fpr = 1.0
            if observed_alerts_count > 0:
                failure_reasons.append(f"False Positive: Scenario expected 0 alerts, observed {observed_alerts_count}")
            if observed_investigations_count > 0:
                failure_reasons.append(f"False Positive: Scenario expected 0 investigations, observed {observed_investigations_count}")
            if len(observed_rules) > 0:
                failure_reasons.append(f"False Positive: Observed unexpected rules: {observed_rules}")
    else:
        # Standard positive detection scenario
        tp = len(matched)
        fn = len(unmatched)
        fp = len(unexpected)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if len(scenario.expected_rules) == 0 else 0.0)
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (1.0 if len(scenario.expected_rules) == 0 else 0.0)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = (fp / (fp + 1)) if fp > 0 else 0.0

        if unmatched:
            failure_reasons.append(f"Missing expected detection rules: {unmatched}")
        if observed_alerts_count < scenario.expected_alerts:
            failure_reasons.append(
                f"Alert count deficient: expected {scenario.expected_alerts}, observed {observed_alerts_count}"
            )
        if observed_investigations_count < scenario.expected_investigations:
            failure_reasons.append(
                f"Investigation count deficient: expected {scenario.expected_investigations}, observed {observed_investigations_count}"
            )

        if len(unmatched) == 0 and observed_alerts_count >= scenario.expected_alerts and observed_investigations_count >= scenario.expected_investigations and len(failure_reasons) == 0:
            pass_status = "PASSED"
        elif len(matched) > 0 or (observed_alerts_count > 0 and scenario.expected_alerts > 0):
            pass_status = "PARTIAL"
        else:
            pass_status = "FAILED"

    return EvaluationResult(
        pass_status=pass_status,
        expected_events_count=len(scenario.expected_rules),
        actual_events_count=observed_events_count,
        expected_rules=scenario.expected_rules,
        actual_rules=observed_rules,
        matched_rules=matched,
        unmatched_rules=unmatched,
        unexpected_rules=unexpected,
        expected_alerts_count=scenario.expected_alerts,
        actual_alerts_count=observed_alerts_count,
        expected_investigations_count=scenario.expected_investigations,
        actual_investigations_count=observed_investigations_count,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        latency_ms=round(latency_ms, 2),
        failure_reasons=failure_reasons,
    )
