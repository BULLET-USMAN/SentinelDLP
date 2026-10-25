"""API v1 Router Definition for SentinelDLP."""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    ai,
    alerts,
    dashboard,
    detection,
    exfiltration,
    health,
    monitoring,
    network,
    placeholder_detection,
    risk,
    scans,
    simulation,
)

api_v1_router = APIRouter()

# Phase 10: Cyberattack Simulation & Detection Validation Laboratory routes
api_v1_router.include_router(
    simulation.router,
    tags=["Simulation Laboratory"],
)

# Phase 9: AI-Powered SOC Analyst & Security Investigation routes
api_v1_router.include_router(
    ai.router,
    tags=["AI SOC Analyst"],
)

# Phase 8: Centralized SOC Dashboard & Unified Search routes
api_v1_router.include_router(
    dashboard.router,
    tags=["SOC Dashboard & Intelligence"],
)

# Health and readiness routes
api_v1_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health & Readiness"],
)

# Phase 2: File Scanner & Inventory routes
api_v1_router.include_router(
    scans.router,
    tags=["File Scanner & Inventory"],
)

# Phase 3: Sensitive Data Detection & Classification routes
api_v1_router.include_router(
    detection.router,
    tags=["Sensitive Data Detection"],
)

# Phase 4: Real-Time File Activity Monitoring routes
api_v1_router.include_router(
    monitoring.router,
    tags=["Real-Time Activity Monitoring"],
)

# Phase 5: Risk Intelligence & Security Alerts routes
api_v1_router.include_router(
    risk.router,
    tags=["Risk Intelligence"],
)
api_v1_router.include_router(
    alerts.router,
    tags=["Security Alerts"],
)

# Phase 6: Data Exfiltration & Event Correlation routes
api_v1_router.include_router(
    exfiltration.router,
    tags=["Data Exfiltration Correlation"],
)

# Phase 7: Advanced Network Traffic Monitoring & Threat Intelligence routes
api_v1_router.include_router(
    network.router,
    tags=["Network Intelligence"],
)

# Placeholder detection routes (Phase 1 legacy compatibility)
api_v1_router.include_router(
    placeholder_detection.router,
    prefix="/detection",
    tags=["Detection Engine (Phase 1 Compatibility)"],
)
