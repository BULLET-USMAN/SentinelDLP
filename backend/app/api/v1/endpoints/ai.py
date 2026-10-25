"""API router endpoints for Phase 9: AI-Powered SOC Analyst and Security Investigation."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.auth import AuthUser, require_analyst, require_readonly
from app.db.session import get_db
from app.ai.client import get_ai_status, get_supported_models_catalog
from app.ai.services.analyst_service import AnalystService
from app.ai.services.report_service import ReportService
from app.ai.services.conversation_service import ConversationService
from app.ai.schemas import (
    AIStatusResponse,
    AIModelInfo,
    AIInvestigationReportResponse,
    AnalyzeInvestigationRequest,
    AnalystFeedbackRequest,
    ChatMessageRequest,
    ChatMessageResponse,
    ConversationSessionSummary,
    ConversationSessionDetail,
)

router = APIRouter(prefix="/ai", tags=["AI SOC Analyst"])


@router.get("/status", response_model=AIStatusResponse)
async def get_status():
    """Retrieve operational status, model availability, and safety guardrails for the AI subsystem."""
    return await get_ai_status()


@router.get("/models", response_model=List[AIModelInfo])
def get_models():
    """List approved lightweight models suitable for local inference and hardware boundaries."""
    return get_supported_models_catalog()


@router.post("/investigations/{investigation_id}/analyze", response_model=AIInvestigationReportResponse)
async def analyze_investigation(
    investigation_id: str,
    payload: Optional[AnalyzeInvestigationRequest] = None,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_analyst),
):
    """Trigger an evidence-grounded AI security investigation report for an exfiltration case."""
    req = payload or AnalyzeInvestigationRequest()
    try:
        report = await AnalystService.analyze_investigation(
            db=db,
            investigation_id=investigation_id,
            analyst_query=req.analyst_query,
            force_refresh=req.force_refresh,
        )
        return report
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI Investigation failed: {str(exc)}",
        )


@router.get("/investigations/{investigation_id}/reports", response_model=List[AIInvestigationReportResponse])
def get_investigation_reports(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve historical AI investigation reports generated for a case."""
    return ReportService.list_reports_for_investigation(db, investigation_id)


@router.get("/reports/{report_id}", response_model=AIInvestigationReportResponse)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve a specific AI investigation report by report_id."""
    report = ReportService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return report


@router.post("/reports/{report_id}/feedback", response_model=AIInvestigationReportResponse)
def submit_report_feedback(
    report_id: str,
    payload: AnalystFeedbackRequest,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_analyst),
):
    """Record human analyst review feedback (USEFUL, INCORRECT, NEEDS_REVIEW) on an AI report."""
    updated = ReportService.record_feedback(
        db=db,
        report_id=report_id,
        status=payload.status,
        notes=payload.notes,
        analyst_name=payload.analyst_name,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return updated


@router.post("/chat", response_model=ChatMessageResponse)
async def chat_with_analyst(
    payload: ChatMessageRequest,
    db: Session = Depends(get_db),
    current_user: AuthUser = Depends(require_analyst),
):
    """Submit a security inquiry to the AI SOC Analyst and receive a grounded response."""
    try:
        return await ConversationService.process_chat_message(
            db=db,
            content=payload.message,
            session_id=payload.session_id,
            investigation_id=payload.investigation_id,
            alert_id=payload.alert_id,
            analyst_name=payload.analyst_name or "soc_analyst",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat processing failure: {str(exc)}",
        )


@router.get("/conversations", response_model=List[ConversationSessionSummary])
def list_conversations(
    limit: int = Query(default=20, ge=1, le=50),
    user_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List recent conversation sessions."""
    return ConversationService.list_sessions(db, limit=limit, user_id=user_id)


@router.get("/conversations/{session_id}", response_model=ConversationSessionDetail)
def get_conversation(
    session_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full conversation history for a specific session."""
    session = ConversationService.get_session_detail(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation session '{session_id}' not found.",
        )
    return session
