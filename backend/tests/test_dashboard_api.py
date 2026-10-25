"""Automated Tests for Phase 8 Centralized SOC Dashboard & Global Search API."""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.main import app
from app.models.detection import FileClassification
from app.models.exfiltration import ExfiltrationInvestigation
from app.models.monitoring import FileActivityEvent
from app.models.network import NetworkSensor, ThreatIntelIndicator
from app.models.risk import RiskAssessment, RuleMatch, SecurityAlert
from app.models.scanner import ScanJob, ScannedFile

client = TestClient(app)


def test_dashboard_overview_endpoint_basic():
    """Verify GET /api/v1/dashboard/overview returns 200 with required structure."""
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()

    assert "security_summary" in data
    assert "risk_distribution" in data
    assert "recent_activity" in data
    assert "risk_trends" in data
    assert "monitoring_status" in data
    assert "priority_queue" in data
    assert "data_freshness_timestamp" in data

    summary = data["security_summary"]
    assert "open_alerts_count" in summary
    assert "high_critical_alerts_count" in summary
    assert "active_investigations_count" in summary
    assert "potential_exfiltrations_count" in summary
    assert "sensitive_files_count" in summary
    assert "active_sensors_count" in summary
    assert "visibility_gaps_count" in summary

    risk_dist = data["risk_distribution"]
    assert "low_count" in risk_dist
    assert "medium_count" in risk_dist
    assert "high_count" in risk_dist
    assert "critical_count" in risk_dist
    assert "average_score" in risk_dist
    assert "total_assessments" in risk_dist
    assert "explanation" in risk_dist

    # Verify monitoring status includes all core capabilities
    comp_ids = [m["component_id"] for m in data["monitoring_status"]]
    assert "file_scanner" in comp_ids
    assert "filesystem_monitor" in comp_ids
    assert "classification_engine" in comp_ids
    assert "risk_engine" in comp_ids
    assert "exfiltration_engine" in comp_ids
    assert "postgresql_db" in comp_ids


def test_dashboard_overview_data_aggregation():
    """Verify that adding security records updates overview counts correctly."""
    db: Session = SessionLocal()
    unique_run = uuid.uuid4().hex[:8]
    try:
        # Create a file activity event first
        fa_event = FileActivityEvent(
            id=str(uuid.uuid4()),
            root_id="test_root",
            event_type="MODIFY",
            relative_path=f"secrets_{unique_run}.key",
            is_directory=False,
            occurred_at=datetime.now(timezone.utc),
        )
        db.add(fa_event)
        db.flush()

        # Create an assessment linked to event
        assessment = RiskAssessment(
            id=str(uuid.uuid4()),
            event_id=fa_event.id,
            root_id="test_root",
            risk_score=85,
            severity="CRITICAL",
            evidence_completeness="COMPLETE",
            detection_confidence="HIGH",
            explanation=f"Critical test risk {unique_run}",
            assessed_at=datetime.now(timezone.utc),
        )
        db.add(assessment)
        db.flush()

        # Add rule match
        rm = RuleMatch(
            assessment_id=assessment.id,
            rule_id="RULE-SENS-DEL",
            rule_name="Sensitive File Deletion",
            score_contribution=85,
            severity_impact="CRITICAL",
        )
        db.add(rm)

        # Create a test alert linked to assessment
        alert_id = str(uuid.uuid4())
        alert = SecurityAlert(
            id=alert_id,
            assessment_id=assessment.id,
            root_id="test_root",
            title=f"Test Threat Alert {unique_run}",
            description=f"Automated threat test {unique_run}",
            severity="CRITICAL",
            risk_score=85,
            status="OPEN",
            deduplication_key=f"dedup-{unique_run}",
            created_at=datetime.now(timezone.utc),
        )
        db.add(alert)

        # Create a test exfiltration investigation
        inv_id = str(uuid.uuid4())
        inv = ExfiltrationInvestigation(
            id=inv_id,
            title=f"Potential Data Exfiltration {unique_run}",
            description=f"Automated test exfiltration correlation {unique_run}",
            severity="HIGH",
            risk_score=75,
            evidence_confidence="HIGH",
            status="INVESTIGATING",
            created_at=datetime.now(timezone.utc),
        )
        db.add(inv)

        # Create a scan job and file for classification
        job = ScanJob(
            id=str(uuid.uuid4()),
            root_id="test_root",
            root_path="/data/test",
            status="completed",
        )
        db.add(job)
        db.flush()

        s_file = ScannedFile(
            scan_job_id=job.id,
            filename=f"secrets_{unique_run}.key",
            relative_path=f"secrets_{unique_run}.key",
            file_extension=".key",
            detected_type="KEY",
            size_bytes=2048,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="scanned",
            created_at=datetime.now(timezone.utc),
        )
        db.add(s_file)
        db.flush()

        # Create a test sensitive classification
        classification = FileClassification(
            scanned_file_id=s_file.id,
            sensitivity_label="RESTRICTED",
            policy_version="1.0.0",
            inspection_status="COMPLETED",
            highest_confidence="HIGH",
            explanation="RSA Private Key detected",
            classified_at=datetime.now(timezone.utc),
        )
        db.add(classification)

        db.commit()

        # Query overview endpoint
        response = client.get("/api/v1/dashboard/overview")
        assert response.status_code == 200
        data = response.json()

        assert data["security_summary"]["open_alerts_count"] >= 1
        assert data["security_summary"]["high_critical_alerts_count"] >= 1
        assert data["security_summary"]["active_investigations_count"] >= 1
        assert data["security_summary"]["sensitive_files_count"] >= 1

        # Check priority queue contains our new alert or investigation
        p_ids = [item["id"] for item in data["priority_queue"]]
        assert alert_id in p_ids or inv_id in p_ids

    finally:
        db.close()


def test_dashboard_global_search():
    """Verify GET /api/v1/dashboard/search performs cross-module matching."""
    db: Session = SessionLocal()
    unique_search = f"srch_{uuid.uuid4().hex[:6]}"
    try:
        # Create a file activity event first
        fa_event = FileActivityEvent(
            id=str(uuid.uuid4()),
            root_id="test_root",
            event_type="MODIFY",
            relative_path=f"secrets_{unique_search}.key",
            is_directory=False,
            occurred_at=datetime.now(timezone.utc),
        )
        db.add(fa_event)
        db.flush()

        # Create assessment for alert
        assessment = RiskAssessment(
            id=str(uuid.uuid4()),
            event_id=fa_event.id,
            root_id="test_root",
            risk_score=75,
            severity="HIGH",
            evidence_completeness="COMPLETE",
            detection_confidence="HIGH",
            explanation=f"High risk secret volume {unique_search}",
            assessed_at=datetime.now(timezone.utc),
        )
        db.add(assessment)
        db.flush()

        # Add searchable threat alert
        alert = SecurityAlert(
            id=str(uuid.uuid4()),
            assessment_id=assessment.id,
            root_id="test_root",
            title=f"Credential Exfil Attempt {unique_search}",
            description=f"Suspicious transfer volume {unique_search}",
            severity="HIGH",
            risk_score=75,
            status="OPEN",
            deduplication_key=f"dedup-{unique_search}",
            created_at=datetime.now(timezone.utc),
        )
        db.add(alert)

        # Add a scan job
        job = ScanJob(
            id=str(uuid.uuid4()),
            root_id="test_root",
            root_path="/data/test",
            status="completed",
        )
        db.add(job)
        db.flush()

        # Add searchable scanned file
        s_file = ScannedFile(
            scan_job_id=job.id,
            filename=f"financial_ledger_{unique_search}.xlsx",
            relative_path=f"finance/2026/financial_ledger_{unique_search}.xlsx",
            file_extension=".xlsx",
            detected_type="DOCUMENT",
            size_bytes=1048576,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="scanned",
            created_at=datetime.now(timezone.utc),
        )
        db.add(s_file)

        # Add searchable threat intel indicator
        indicator = ThreatIntelIndicator(
            indicator_type="DOMAIN",
            indicator_value=f"drop-{unique_search}.darknet",
            category="MALICIOUS",
            source_feed="LOCAL_ANALYST",
            confidence="HIGH",
            description=f"Suspected C2 drop {unique_search}",
            created_at=datetime.now(timezone.utc),
        )
        db.add(indicator)
        db.commit()

        # Search for unique token
        res = client.get(f"/api/v1/dashboard/search?q={unique_search}")
        assert res.status_code == 200
        search_data = res.json()

        assert search_data["total_results"] >= 3
        types_found = {r["result_type"] for r in search_data["results"]}
        assert "ALERT" in types_found
        assert "FILE" in types_found
        assert "INDICATOR" in types_found

        # Verify links are appropriate for frontend routing
        for item in search_data["results"]:
            assert item["link_tab"] in ["alerts", "investigations", "scanner", "detection", "network", "risk"]

    finally:
        db.close()


def test_dashboard_search_empty_and_validation():
    """Verify search input validation and handling of non-existent queries."""
    # Blank query fails validation
    res = client.get("/api/v1/dashboard/search?q=")
    assert res.status_code == 422

    # Non-existent query returns empty list gracefully
    res_none = client.get("/api/v1/dashboard/search?q=xyznonexistenttoken9999999999")
    assert res_none.status_code == 200
    assert res_none.json()["total_results"] == 0
    assert res_none.json()["results"] == []
