"""Aggregate Detection Metrics Service for Phase 10 Validation Laboratory."""

import json
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.simulation import SimulationRun, SimulationResult
from app.simulation.schemas import GlobalDetectionMetrics


class MetricsService:
    """Computes global confusion matrix and detection accuracy statistics."""

    @staticmethod
    def get_global_metrics(db: Session) -> GlobalDetectionMetrics:
        """Calculate platform-wide detection accuracy metrics across all runs."""
        runs = db.query(SimulationRun).all()
        results = db.query(SimulationResult).all()

        total_runs = len(runs)
        if total_runs == 0:
            return GlobalDetectionMetrics()

        passed = sum(1 for r in runs if r.status == "PASSED")
        failed = sum(1 for r in runs if r.status == "FAILED")
        partial = sum(1 for r in runs if r.status == "PARTIAL")

        tp = 0
        fp = 0
        fn = 0
        tn = 0
        latencies = []

        for res in results:
            matched = json.loads(res.matched_rules_json)
            unmatched = json.loads(res.unmatched_rules_json)
            unexpected = json.loads(res.unexpected_rules_json)

            tp += len(matched)
            fn += len(unmatched)
            fp += len(unexpected)

            # Check if this was a negative control run
            if res.expected_alerts_count == 0 and len(json.loads(res.expected_rules_json)) == 0:
                if res.pass_status == "PASSED":
                    tn += 1

            if res.latency_ms > 0:
                latencies.append(res.latency_ms)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (1.0 if fn == 0 else 0.0)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        mean_latency = (sum(latencies) / len(latencies)) if latencies else 0.0

        return GlobalDetectionMetrics(
            total_runs=total_runs,
            passed_runs=passed,
            failed_runs=failed,
            partial_runs=partial,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            overall_precision=round(precision, 4),
            overall_recall=round(recall, 4),
            overall_f1=round(f1, 4),
            overall_fpr=round(fpr, 4),
            mean_latency_ms=round(mean_latency, 2),
        )
