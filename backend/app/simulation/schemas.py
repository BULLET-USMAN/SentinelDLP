"""Pydantic schemas for the Cyberattack Simulation and Detection Validation Lab."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ScenarioCategory(str, Enum):
    BENIGN_BASELINE = "BENIGN_BASELINE"
    DATA_DISCOVERY = "DATA_DISCOVERY"
    RAPID_MODIFICATION = "RAPID_MODIFICATION"
    BULK_RENAME = "BULK_RENAME"
    STAGING_ARCHIVE = "STAGING_ARCHIVE"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"
    COVERAGE_GAP = "COVERAGE_GAP"
    EVENT_IDEMPOTENCY = "EVENT_IDEMPOTENCY"
    AI_VALIDATION = "AI_VALIDATION"


class SimulationStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class CoverageLevel(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_TESTED = "NOT_TESTED"


class ScenarioDefinition(BaseModel):
    """Catalog metadata and detection expectations for a simulation scenario."""

    scenario_id: str = Field(..., description="Unique scenario identifier (e.g. SCEN-01)")
    name: str = Field(..., description="Descriptive scenario name")
    category: ScenarioCategory
    description: str
    target_subsystems: List[str]
    mitre_techniques: List[str] = Field(default_factory=list)
    expected_rules: List[str] = Field(default_factory=list)
    expected_alerts: int = 0
    expected_investigations: int = 0
    negative_control: bool = False
    estimated_duration_sec: int = 3


class ScenarioRunRequest(BaseModel):
    """Payload to trigger execution of a scenario."""

    scenario_id: str
    custom_seed: Optional[int] = 42
    auto_cleanup: bool = True


class SimulationStepLog(BaseModel):
    """Single step log entry emitted during scenario execution."""

    step_number: int
    action: str
    status: str  # 'SUCCESS', 'INFO', 'WARN', 'ERROR'
    message: str
    timestamp: str


class SimulationResultResponse(BaseModel):
    """Detailed validation evaluation comparing expected vs observed security artifacts."""

    id: str
    run_id: str
    pass_status: str
    expected_events_count: int
    actual_events_count: int
    expected_rules: List[str]
    actual_rules: List[str]
    matched_rules: List[str]
    unmatched_rules: List[str]
    unexpected_rules: List[str]
    expected_alerts_count: int
    actual_alerts_count: int
    expected_investigations_count: int
    actual_investigations_count: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    latency_ms: float
    failure_reasons: List[str]


class SimulationRunResponse(BaseModel):
    """Full details of a simulation execution run."""

    id: str
    scenario_id: str
    scenario_name: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: int = 0
    summary: Optional[str] = None
    execution_logs: List[SimulationStepLog] = Field(default_factory=list)
    result: Optional[SimulationResultResponse] = None


class GlobalDetectionMetrics(BaseModel):
    """Aggregate detection statistics across simulation runs."""

    total_runs: int = 0
    passed_runs: int = 0
    failed_runs: int = 0
    partial_runs: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    overall_f1: float = 0.0
    overall_fpr: float = 0.0
    mean_latency_ms: float = 0.0


class SubsystemCoverageItem(BaseModel):
    """Coverage status between a scenario and a platform subsystem."""

    subsystem: str
    scenario_id: str
    scenario_name: str
    coverage_level: CoverageLevel
    rules_evaluated: List[str] = Field(default_factory=list)
    notes: str = ""


class SimulationReportResponse(BaseModel):
    """Rendered markdown report for an executed simulation."""

    id: str
    run_id: str
    title: str
    markdown_content: str
    created_at: str
