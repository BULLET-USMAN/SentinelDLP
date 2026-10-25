"""Secure execution harness and audit logging for AI SOC Analyst tools."""

import json
import time
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.ai.tools.registry import get_tool_handler
from app.ai.security.permissions import is_tool_authorized
from app.ai.config import ai_config
from app.models.ai import AIToolAuditEvent


class ToolExecutionResult:
    def __init__(
        self,
        tool_name: str,
        success: bool,
        data: Any = None,
        error_message: Optional[str] = None,
        duration_ms: int = 0,
    ):
        self.tool_name = tool_name
        self.success = success
        self.data = data
        self.error_message = error_message
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
        }


def execute_tool_call(
    db: Session,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: Optional[str] = None,
    report_id: Optional[str] = None,
    current_tool_call_count: int = 0,
) -> ToolExecutionResult:
    """Execute a single server-controlled tool call with security guardrails and audit logging."""
    start_time = time.time()

    # 1. Check Tool Authorization (Read-Only Enforcement)
    if not is_tool_authorized(tool_name):
        duration_ms = int((time.time() - start_time) * 1000)
        _record_audit(
            db, session_id, report_id, tool_name, arguments, "DENIED",
            "Tool execution denied: unauthorized or disruptive operation", duration_ms
        )
        return ToolExecutionResult(
            tool_name=tool_name,
            success=False,
            error_message=f"Unauthorized tool: '{tool_name}' is not in the approved read-only allowlist.",
            duration_ms=duration_ms,
        )

    # 2. Check Execution Bounds (Anti-Infinite Loop / Anti-Resource Exhaustion)
    if current_tool_call_count >= ai_config.MAX_TOOL_CALLS_PER_INVESTIGATION:
        duration_ms = int((time.time() - start_time) * 1000)
        _record_audit(
            db, session_id, report_id, tool_name, arguments, "BOUND_EXCEEDED",
            f"Maximum tool calls limit ({ai_config.MAX_TOOL_CALLS_PER_INVESTIGATION}) reached", duration_ms
        )
        return ToolExecutionResult(
            tool_name=tool_name,
            success=False,
            error_message=f"Tool call bound exceeded: Maximum {ai_config.MAX_TOOL_CALLS_PER_INVESTIGATION} calls allowed per investigation.",
            duration_ms=duration_ms,
        )

    handler = get_tool_handler(tool_name)
    if not handler:
        duration_ms = int((time.time() - start_time) * 1000)
        _record_audit(
            db, session_id, report_id, tool_name, arguments, "ERROR",
            f"No handler registered for tool '{tool_name}'", duration_ms
        )
        return ToolExecutionResult(
            tool_name=tool_name,
            success=False,
            error_message=f"Unknown tool '{tool_name}'.",
            duration_ms=duration_ms,
        )

    # 3. Controlled Execution
    try:
        data = handler(db, **arguments)
        duration_ms = int((time.time() - start_time) * 1000)

        # Extract primary resource ID if present in arguments
        resource_id = (
            arguments.get("alert_id")
            or arguments.get("investigation_id")
            or arguments.get("file_id")
            or arguments.get("event_id")
            or arguments.get("assessment_id")
            or arguments.get("sensor_id")
            or arguments.get("technique_id")
        )

        _record_audit(
            db, session_id, report_id, tool_name, arguments, "SUCCESS",
            None, duration_ms, str(resource_id) if resource_id else None
        )

        return ToolExecutionResult(
            tool_name=tool_name,
            success=True,
            data=data,
            duration_ms=duration_ms,
        )
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        _record_audit(
            db, session_id, report_id, tool_name, arguments, "ERROR",
            str(exc), duration_ms
        )
        return ToolExecutionResult(
            tool_name=tool_name,
            success=False,
            error_message=f"Tool execution failed: {str(exc)}",
            duration_ms=duration_ms,
        )


def _record_audit(
    db: Session,
    session_id: Optional[str],
    report_id: Optional[str],
    tool_name: str,
    arguments: Dict[str, Any],
    status: str,
    error_message: Optional[str],
    duration_ms: int,
    resource_id: Optional[str] = None,
):
    """Write an immutable audit entry to PostgreSQL."""
    try:
        audit_event = AIToolAuditEvent(
            session_id=session_id,
            report_id=report_id,
            tool_name=tool_name,
            arguments_json=json.dumps(arguments, default=str),
            resource_id=resource_id,
            status=status,
            error_message=error_message,
            execution_duration_ms=duration_ms,
        )
        db.add(audit_event)
        db.commit()
    except Exception as exc:
        db.rollback()
        # Fallback console audit if DB commit fails
        print(f"[AUDIT FAILURE] Failed to write AIToolAuditEvent: {exc}")
