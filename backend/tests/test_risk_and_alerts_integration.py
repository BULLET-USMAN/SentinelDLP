"""Integration tests for Risk Engine and Security Alert Lifecycle (Phase 5).

Tests:
- End-to-end evaluation and database persistence
- Idempotent assessment processing
- Alert generation, deduplication, and suppression
- Analyst triage lifecycle transitions and audit trail
- REST API endpoints under /api/v1/risk and /api/v1/alerts
"""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from app.db.session import SessionLocal
from app.main import app
from app.models.monitoring import FileActivityEvent
from app.models.risk import AlertAuditLog, RiskAssessment, SecurityAlert
from app.risk.engine import risk_engine
from app.risk.severity import AlertStatus


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def clean_db():
    """Provide a database session and clean up test records afterward."""
    db = SessionLocal()
    yield db
    # Cleanup any test artifacts
    db.query(AlertAuditLog).filter(AlertAuditLog.performed_by.in_(("test_analyst", "sentinel_risk_engine", "system_deduplicator"))).delete()
    db.query(SecurityAlert).filter(SecurityAlert.root_id == "test_phase5_root").delete()
    db.query(RiskAssessment).filter(RiskAssessment.root_id == "test_phase5_root").delete()
    db.query(FileActivityEvent).filter(FileActivityEvent.root_id == "test_phase5_root").delete()
    db.commit()
    db.close()


def test_idempotent_event_evaluation(clean_db):
    """Evaluating the exact same event multiple times produces the identical assessment without duplicate rows."""
    event_id = str(uuid.uuid4())
    event = FileActivityEvent(
        id=event_id,
        root_id="test_phase5_root",
        event_type="FILE_MODIFIED",
        is_directory=False,
        relative_path="docs/financial_plan.docx",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
        sha256_hash="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    )
    clean_db.add(event)
    clean_db.commit()

    # First evaluation
    assessment1 = risk_engine.evaluate_event(event, clean_db)
    clean_db.commit()

    assert assessment1 is not None
    assert assessment1.risk_score == 25  # RESTRICTED modification = 25 points
    assessment1_id = assessment1.id

    # Second evaluation on same event
    assessment2 = risk_engine.evaluate_event(event, clean_db)
    clean_db.commit()

    assert assessment2.id == assessment1_id
    total_assessments = clean_db.query(RiskAssessment).filter(RiskAssessment.event_id == event_id).count()
    assert total_assessments == 1


def test_alert_generation_and_suppression(clean_db):
    """Events with score >= 30 create an alert; rapid duplicates are suppressed with repeat_count incremented."""
    event_id_1 = str(uuid.uuid4())
    # Create extension change to suspicious extension on RESTRICTED file -> Score 67 (HIGH)
    event1 = FileActivityEvent(
        id=event_id_1,
        root_id="test_phase5_root",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="data/records.locked",
        previous_relative_path="data/records.docx",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
    )
    clean_db.add(event1)
    clean_db.commit()

    assessment1 = risk_engine.evaluate_event(event1, clean_db)
    clean_db.commit()

    assert assessment1.risk_score >= 60

    # Verify SecurityAlert created
    alert1 = clean_db.query(SecurityAlert).filter(SecurityAlert.assessment_id == assessment1.id).first()
    assert alert1 is not None
    assert alert1.status == "OPEN"
    assert alert1.repeat_count == 1
    alert_id = alert1.id

    # Second similar event on same file path within suppression window
    event_id_2 = str(uuid.uuid4())
    event2 = FileActivityEvent(
        id=event_id_2,
        root_id="test_phase5_root",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="data/records.locked",
        previous_relative_path="data/records.docx",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
    )
    clean_db.add(event2)
    clean_db.commit()

    risk_engine.evaluate_event(event2, clean_db)
    clean_db.commit()

    # Alert count should still be 1 (suppressed duplicate), but repeat_count should be 2
    clean_db.refresh(alert1)
    assert alert1.repeat_count == 2

    # Verify suppression audit log
    audit_logs = clean_db.query(AlertAuditLog).filter(AlertAuditLog.alert_id == alert_id).all()
    actions = [a.action for a in audit_logs]
    assert "alert_created" in actions
    assert "suppressed_duplicate" in actions


def test_alert_lifecycle_status_transitions_and_api(client, clean_db):
    """Test full analyst lifecycle: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED via REST API."""
    event_id = str(uuid.uuid4())
    event = FileActivityEvent(
        id=event_id,
        root_id="test_phase5_root",
        event_type="FILE_RENAMED",
        is_directory=False,
        relative_path="secrets/keys.locked",
        previous_relative_path="secrets/keys.txt",
        occurred_at=datetime.now(timezone.utc),
        collected_at=datetime.now(timezone.utc),
        status="processed",
        sensitivity_label="RESTRICTED",
    )
    clean_db.add(event)
    clean_db.commit()

    assessment = risk_engine.evaluate_event(event, clean_db)
    clean_db.commit()

    alert = clean_db.query(SecurityAlert).filter(SecurityAlert.assessment_id == assessment.id).first()
    assert alert is not None
    alert_id = alert.id

    # 1. Transition: OPEN -> ACKNOWLEDGED
    res_ack = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED", "analyst_notes": "Triage acknowledged by analyst", "performed_by": "test_analyst"},
    )
    assert res_ack.status_code == 200
    assert res_ack.json()["status"] == "ACKNOWLEDGED"

    # 2. Transition: ACKNOWLEDGED -> INVESTIGATING
    res_inv = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "INVESTIGATING", "analyst_notes": "Correlating host event logs", "performed_by": "test_analyst"},
    )
    assert res_inv.status_code == 200
    assert res_inv.json()["status"] == "INVESTIGATING"

    # 3. Transition: INVESTIGATING -> RESOLVED
    res_res = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "RESOLVED", "analyst_notes": "Verified scheduled backup encryption tool", "performed_by": "test_analyst"},
    )
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "RESOLVED"
    assert res_res.json()["resolution_notes"] == "Verified scheduled backup encryption tool"

    # 4. Invalid Transition: RESOLVED -> INVESTIGATING should fail (only OPEN is allowed from RESOLVED)
    res_invalid = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "INVESTIGATING", "analyst_notes": "Invalid jump", "performed_by": "test_analyst"},
    )
    assert res_invalid.status_code == 400
    assert "Invalid status transition" in res_invalid.json()["detail"]


def test_api_risk_and_alerts_query_endpoints(client, clean_db):
    """Test retrieval and metrics queries across /api/v1/risk and /api/v1/alerts."""
    # List rules catalog
    rules_res = client.get("/api/v1/risk/rules")
    assert rules_res.status_code == 200
    catalog = rules_res.json()
    assert len(catalog) == 8
    rule_ids = [r["rule_id"] for r in catalog]
    assert "RULE-SENS-MOD" in rule_ids
    assert "RULE-BULK-RENAME" in rule_ids
    assert "RULE-COVERAGE-WARN" in rule_ids

    # List assessments
    assessments_res = client.get("/api/v1/risk/assessments")
    assert assessments_res.status_code == 200
    assert "items" in assessments_res.json()
    assert "total" in assessments_res.json()

    # Get risk statistics
    risk_stats = client.get("/api/v1/risk/statistics")
    assert risk_stats.status_code == 200
    assert "score_distribution" in risk_stats.json()
    assert "average_score" in risk_stats.json()

    # List alerts
    alerts_res = client.get("/api/v1/alerts")
    assert alerts_res.status_code == 200
    assert "items" in alerts_res.json()

    # Get alert statistics
    alert_stats = client.get("/api/v1/alerts/statistics")
    assert alert_stats.status_code == 200
    assert "open_count" in alert_stats.json()
    assert "by_severity" in alert_stats.json()
