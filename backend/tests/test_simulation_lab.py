"""Unit and Integration Tests for Phase 10: Cyberattack Simulation & Detection Validation Laboratory."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.simulation.safety import (
    validate_sandbox_path,
    is_safe_sandbox_path,
    SimulationSafetyViolation,
    get_sandbox_root,
)
from app.simulation.generator import SyntheticDataGenerator
from app.simulation.scenario_registry import get_all_scenarios, get_scenario


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_list_all_eleven_scenarios(client):
    """Verify that all 11 predefined scenarios are listed with complete metadata."""
    res = client.get("/api/v1/simulation/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) == 11

    scenario_ids = [s["scenario_id"] for s in scenarios]
    for i in range(1, 12):
        expected_id = f"SCEN-{i:02d}"
        assert expected_id in scenario_ids

    # Verify key schema attributes on a sample scenario
    sample = next(s for s in scenarios if s["scenario_id"] == "SCEN-07")
    assert sample["name"] == "Potential Data Exfiltration (Multi-Signal Correlation)"
    assert "MONITORING" in sample["target_subsystems"]
    assert "EXFILTRATION" in sample["target_subsystems"]
    assert sample["expected_investigations"] == 1


def test_get_scenario_detail(client):
    """Verify individual scenario retrieval and 404 on invalid ID."""
    res = client.get("/api/v1/simulation/scenarios/SCEN-01")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario_id"] == "SCEN-01"
    assert data["negative_control"] is True

    res_err = client.get("/api/v1/simulation/scenarios/SCEN-NONEXISTENT")
    assert res_err.status_code == 404


def test_safety_and_sandbox_confinement():
    """Verify that path safety mechanisms reject any paths outside sample_data/simulation_lab."""
    sandbox_root = get_sandbox_root()
    assert sandbox_root.is_dir()

    # Valid internal path
    safe_target = sandbox_root / "test_run_123" / "artifact.csv"
    assert is_safe_sandbox_path(safe_target) is True
    validated = validate_sandbox_path(safe_target)
    assert validated == safe_target.resolve()

    # Disallowed external paths
    with pytest.raises(SimulationSafetyViolation):
        validate_sandbox_path(sandbox_root.parent / "escape.txt")

    with pytest.raises(SimulationSafetyViolation):
        validate_sandbox_path(Path("C:/Windows/System32/malicious.dll") if "\\" in str(sandbox_root) else Path("/etc/passwd"))


def test_synthetic_data_generator():
    """Verify generation of harmless synthetic files, PII, Luhn-valid cards, and archives."""
    gen = SyntheticDataGenerator(run_id="test-gen-run", seed=42)
    try:
        # 1. Benign file
        benign_py = gen.create_benign_file("test_check.py")
        assert benign_py.exists()
        assert "check_disk_space" in benign_py.read_text(encoding="utf-8")

        # 2. Sensitive CNIC file
        cnic_csv = gen.create_sensitive_cnic_file("test_cnic.csv")
        assert cnic_csv.exists()
        content_cnic = cnic_csv.read_text(encoding="utf-8")
        assert "national_identity" in content_cnic
        assert "-" in content_cnic  # Standard CNIC separator

        # 3. Sensitive financial file
        fin_json = gen.create_sensitive_financial_file("test_cards.json")
        assert fin_json.exists()
        content_fin = fin_json.read_text(encoding="utf-8")
        assert "primary_account_number" in content_fin

        # 4. Sensitive credentials
        cred_env = gen.create_sensitive_credentials_file("test_tokens.env")
        assert cred_env.exists()
        assert "AWS_ACCESS_KEY_ID=AKIA" in cred_env.read_text(encoding="utf-8")

        # 5. Staging ZIP archive
        zip_path = gen.create_staging_archive("test_staged.zip")
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"
    finally:
        cleaned = gen.cleanup()
        assert cleaned >= 5
        assert not gen.run_dir.exists()


def test_execute_scen_01_benign_baseline(client):
    """Test execution of Scenario 1 (Benign Baseline), verifying zero false-positive alerts."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-01", "custom_seed": 101, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["scenario_id"] == "SCEN-01"
    assert run_data["status"] == "PASSED"
    assert len(run_data["execution_logs"]) >= 3

    result = run_data["result"]
    assert result is not None
    assert result["pass_status"] == "PASSED"
    assert result["actual_alerts_count"] == 0
    assert result["actual_investigations_count"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0


def test_execute_scen_02_sensitive_discovery(client):
    """Test execution of Scenario 2 (Sensitive Discovery) detecting PII, cards, and credentials."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-02", "custom_seed": 202, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"

    result = run_data["result"]
    assert result is not None
    assert "RULE-PII-CNIC-PK" in result["matched_rules"]
    assert "RULE-FIN-PAYMENT-CARD" in result["matched_rules"]
    assert "RULE-CRED-API-TOKEN" in result["matched_rules"]


def test_execute_scen_07_exfiltration_correlation(client):
    """Test execution of Scenario 7 (Exfiltration Chain) triggering correlation and investigation."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-07", "custom_seed": 707, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"

    result = run_data["result"]
    assert result is not None
    assert result["actual_investigations_count"] >= 1
    assert "EXFIL-003" in result["matched_rules"] or "EXFIL-007" in result["matched_rules"]


def test_execute_scen_08_negative_control(client):
    """Test execution of Scenario 8 (Negative Control) verifying zero false investigations."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-08", "custom_seed": 808, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"

    result = run_data["result"]
    assert result is not None
    assert result["actual_investigations_count"] == 0
    assert result["actual_alerts_count"] == 0


def test_execute_scen_11_ai_analyst_evaluation(client):
    """Test execution of Scenario 11 verifying anti-prompt injection and AI report generation."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-11", "custom_seed": 111, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"

    result = run_data["result"]
    assert result is not None
    assert "AI-VERIFIED-REPORT" in result["matched_rules"]
    assert "PROMPT-INJECTION-NEUTRALIZED" in result["matched_rules"]


def test_simulation_global_metrics(client):
    """Verify aggregated confusion matrix and detection accuracy metrics calculation."""
    res = client.get("/api/v1/simulation/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["total_runs"] >= 1
    assert metrics["passed_runs"] >= 1
    assert "overall_precision" in metrics
    assert "overall_recall" in metrics
    assert "overall_f1" in metrics


def test_subsystem_coverage_matrix(client):
    """Verify subsystem test coverage endpoint returns mapping for all subsystems."""
    res = client.get("/api/v1/simulation/coverage")
    assert res.status_code == 200
    coverage = res.json()
    assert len(coverage) >= 15

    subsystems = {item["subsystem"] for item in coverage}
    assert "SCANNER" in subsystems
    assert "MONITORING" in subsystems
    assert "RISK_ENGINE" in subsystems
    assert "EXFILTRATION" in subsystems
    assert "NETWORK" in subsystems
    assert "AI_ANALYST" in subsystems


def test_simulation_report_generation(client):
    """Verify markdown report retrieval for an executed simulation run."""
    # Run a quick scenario first
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-01", "custom_seed": 999, "auto_cleanup": True},
    )
    run_id = res.json()["id"]

    res_report = client.get(f"/api/v1/simulation/reports/{run_id}")
    assert res_report.status_code == 200
    report = res_report.json()
    assert report["run_id"] == run_id
    assert "# SentinelDLP Security Validation Report" in report["markdown_content"]
    assert "Executive Summary" in report["markdown_content"]
    assert "Execution Step Timeline" in report["markdown_content"]


def test_execute_scen_03_rapid_modification(client):
    """Test execution of Scenario 3 (Rapid Sensitive File Modification)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-03", "custom_seed": 303, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "RULE-RAPID-MOD" in result["matched_rules"]
    assert "RULE-SENS-MOD" in result["matched_rules"]


def test_execute_scen_04_bulk_renaming(client):
    """Test execution of Scenario 4 (Bulk File Renaming / Tampering)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-04", "custom_seed": 404, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "RULE-BULK-RENAME" in result["matched_rules"]
    assert "RULE-EXT-CHANGE" in result["matched_rules"]


def test_execute_scen_05_archive_staging(client):
    """Test execution of Scenario 5 (Archive Activity / Staging)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-05", "custom_seed": 505, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "EXFIL-002" in result["matched_rules"]


def test_execute_scen_06_network_traffic_anomalies(client):
    """Test execution of Scenario 6 (Network Anomalies: Outbound Spike, Multi-Port, DNS Entropy)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-06", "custom_seed": 606, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "NET-001" in result["matched_rules"]
    assert "NET-003" in result["matched_rules"]
    assert "NET-005" in result["matched_rules"]


def test_execute_scen_09_coverage_gap(client):
    """Test execution of Scenario 9 (Coverage Gap Diagnostic)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-09", "custom_seed": 909, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "RULE-COVERAGE-WARN" in result["matched_rules"]
    assert "NET-009" in result["matched_rules"]


def test_execute_scen_10_duplicate_and_out_of_order(client):
    """Test execution of Scenario 10 (Event Idempotency & Repeat Tracking)."""
    res = client.post(
        "/api/v1/simulation/runs",
        json={"scenario_id": "SCEN-10", "custom_seed": 1010, "auto_cleanup": True},
    )
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "PASSED"
    result = run_data["result"]
    assert "RULE-REPEAT-CHANGE" in result["matched_rules"]
