"""Placeholder Detection API Module for SentinelDLP.

=============================================================================
ARCHITECTURAL NOTICE - PHASE 1
=============================================================================
This module is a placeholder reserving API routes and defining structural
conventions for future phases (Phase 2: Detection Engine, Phase 3: Exfiltration
Heuristics, Phase 4: AI Analysis).

In strict adherence to Phase 1 boundaries:
- NO file scanning is executed here.
- NO pattern matching is performed here.
- NO simulated threats or fake incidents are generated.
=============================================================================
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter()


class PhaseRoadmapInfo(BaseModel):
    """Schema describing future phase integration points."""

    module: str = Field(..., description="Target architectural module")
    phase_target: str = Field(..., description="Target phase for implementation")
    status: str = Field(default="planned", description="Current implementation status")
    description: str = Field(..., description="Overview of planned capability")


@router.get(
    "/status",
    response_model=PhaseRoadmapInfo,
    summary="Detection Engine Architecture Status",
    description="Reports the architectural integration status of detection services.",
)
async def get_detection_status() -> PhaseRoadmapInfo:
    """Return the planned roadmap status for detection services."""
    return PhaseRoadmapInfo(
        module="Detection & Exfiltration Analysis Engine",
        phase_target="Phase 2+",
        status="foundation_active_detection_deferred",
        description=(
            "Phase 1 foundation established. Detection engines, content inspection, "
            "and exfiltration behavioral analysis are scheduled for subsequent phases."
        ),
    )


@router.post(
    "/inspect",
    summary="Content Inspection Hook (Placeholder)",
    description="Reserved hook for Phase 2 data classification.",
)
async def inspect_content_placeholder() -> None:
    """Explicitly inactive hook during Phase 1."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Content inspection engine is reserved for Phase 2 implementation.",
    )
