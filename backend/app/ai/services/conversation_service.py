"""Conversation session and chat memory management service for AI SOC Analyst."""

import json
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.ai import AIConversationSession, AIConversationMessage
from app.ai.client import get_ai_provider
from app.ai.config import ai_config
from app.ai.tools.registry import TOOL_DEFINITIONS
from app.ai.prompts.system_prompt import AI_SOC_SYSTEM_PROMPT
from app.ai.security.sanitization import sanitize_text
from app.ai.schemas import (
    ChatMessageResponse,
    ConversationSessionSummary,
    ConversationSessionDetail,
)


class ConversationService:
    """Manages bounded conversation sessions and message memory."""

    @classmethod
    async def process_chat_message(
        cls,
        db: Session,
        content: str,
        session_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        analyst_name: str = "soc_analyst",
    ) -> ChatMessageResponse:
        sanitized_input = sanitize_text(content)

        # 1. Resolve or create conversation session
        session = None
        if session_id:
            session = db.query(AIConversationSession).filter(AIConversationSession.id == session_id.strip()).first()

        if not session:
            title_preview = sanitized_input[:40] + "..." if len(sanitized_input) > 40 else sanitized_input
            session = AIConversationSession(
                investigation_id=investigation_id,
                alert_id=alert_id,
                user_id=analyst_name,
                title=f"Inquiry: {title_preview}",
                model_id=ai_config.OLLAMA_MODEL if ai_config.AI_PROVIDER_TYPE == "ollama" else "mock-sentinel-v1",
            )
            db.add(session)
            db.commit()
            db.refresh(session)

        # 2. Record User Message
        user_msg = AIConversationMessage(
            session_id=session.id,
            role="user",
            content=sanitized_input,
            sanitized=True,
        )
        db.add(user_msg)
        db.commit()

        # 3. Assemble bounded message history
        history_msgs = (
            db.query(AIConversationMessage)
            .filter(AIConversationMessage.session_id == session.id)
            .order_by(AIConversationMessage.created_at.asc())
            .limit(ai_config.MAX_CONVERSATION_HISTORY_MESSAGES)
            .all()
        )

        formatted_messages = [{"role": "system", "content": AI_SOC_SYSTEM_PROMPT}]
        for hm in history_msgs:
            formatted_messages.append({"role": hm.role, "content": hm.content})

        # 4. Invoke AI Provider
        provider = get_ai_provider()
        ai_response = await provider.generate_chat(formatted_messages, tools=TOOL_DEFINITIONS)

        assistant_content = ai_response.get("content", "Analysis completed.")
        evidence_refs = ai_response.get("evidence_references", [])
        tool_invocations = ai_response.get("tool_invocations", [])

        # 5. Record Assistant Message
        assistant_msg = AIConversationMessage(
            session_id=session.id,
            role="assistant",
            content=assistant_content,
            sanitized=True,
            evidence_references_json=json.dumps(evidence_refs, default=str),
            tool_invocations_json=json.dumps(tool_invocations, default=str),
        )
        db.add(assistant_msg)
        session.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(assistant_msg)

        return ChatMessageResponse(
            message_id=assistant_msg.id,
            session_id=session.id,
            role="assistant",
            content=assistant_msg.content,
            evidence_references=evidence_refs,
            tool_invocations=tool_invocations,
            created_at=assistant_msg.created_at,
        )

    @classmethod
    def list_sessions(
        cls, db: Session, limit: int = 20, user_id: Optional[str] = None
    ) -> List[ConversationSessionSummary]:
        """List recent conversation sessions."""
        query = db.query(AIConversationSession)
        if user_id:
            query = query.filter(AIConversationSession.user_id == user_id)

        sessions = query.order_by(AIConversationSession.updated_at.desc()).limit(limit).all()
        summaries = []
        for s in sessions:
            count = db.query(AIConversationMessage).filter(AIConversationMessage.session_id == s.id).count()
            summaries.append(
                ConversationSessionSummary(
                    id=s.id,
                    investigation_id=s.investigation_id,
                    alert_id=s.alert_id,
                    title=s.title,
                    status=s.status,
                    model_id=s.model_id,
                    message_count=count,
                    created_at=s.created_at,
                    updated_at=s.updated_at,
                )
            )
        return summaries

    @classmethod
    def get_session_detail(cls, db: Session, session_id: str) -> Optional[ConversationSessionDetail]:
        """Retrieve full conversation history for a specific session."""
        session = db.query(AIConversationSession).filter(AIConversationSession.id == session_id.strip()).first()
        if not session:
            return None

        messages = (
            db.query(AIConversationMessage)
            .filter(AIConversationMessage.session_id == session.id)
            .order_by(AIConversationMessage.created_at.asc())
            .all()
        )

        message_items = []
        for m in messages:
            try:
                refs = json.loads(m.evidence_references_json or "[]")
            except Exception:
                refs = []
            try:
                tools = json.loads(m.tool_invocations_json or "[]")
            except Exception:
                tools = []

            message_items.append(
                ChatMessageResponse(
                    message_id=m.id,
                    session_id=session.id,
                    role=m.role,
                    content=m.content,
                    evidence_references=refs,
                    tool_invocations=tools,
                    created_at=m.created_at,
                )
            )

        return ConversationSessionDetail(
            id=session.id,
            investigation_id=session.investigation_id,
            alert_id=session.alert_id,
            title=session.title,
            status=session.status,
            model_id=session.model_id,
            messages=message_items,
            created_at=session.created_at,
            updated_at=session.updated_at,
        )
