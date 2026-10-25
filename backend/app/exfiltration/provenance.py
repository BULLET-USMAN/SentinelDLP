"""Evidence Provenance and Relationship Taxonomy for SentinelDLP (Phase 6).

Forensic Integrity Principles:
1. Strict Provenance Tracking: Every evidence item must record where and how it was acquired:
   - OBSERVED: Directly recorded by local filesystem monitor or verifiable OS telemetry.
   - IMPORTED: Ingested from external logs, gateways, or perimeter proxies.
   - LAB_SIMULATED: Generated synthetically by automated testing harness or lab exercise.
   - INFERRED: Derived or aggregated by the correlation engine.

2. Causal Modesty & Relationship Taxonomy:
   - temporal: Events occurred in chronological proximity within a bounded time window (correlation, not causation).
   - circumstantial: Events share contextual attributes (e.g. filename stem, user identity, process ID).
   - verified: Cryptographic hash match, verifiable handle access, or end-to-end audit trace.
"""

from enum import Enum


class EvidenceProvenance(str, Enum):
    """Source authenticity and capture lineage of evidence."""
    OBSERVED = "OBSERVED"
    IMPORTED = "IMPORTED"
    LAB_SIMULATED = "LAB_SIMULATED"
    INFERRED = "INFERRED"


class RelationshipType(str, Enum):
    """Nature of the relationship linking disparate signals."""
    TEMPORAL = "temporal"
    CIRCUMSTANTIAL = "circumstantial"
    VERIFIED = "verified"


class InvestigationStatus(str, Enum):
    """Lifecycle triage states for an exfiltration investigation."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceCompleteness(str, Enum):
    """Completeness of the evidentiary chain."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"


class EvidenceConfidence(str, Enum):
    """Confidence rating in the correlation findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
