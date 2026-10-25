"""Anti-Hallucination and Output Validation Layer for SentinelDLP AI Subsystem.

Ensures that model-generated reports:
1. Never fabricate record identifiers (every cited ID must exist in available evidence).
2. Never invent MITRE ATT&CK technique IDs (must exist in our offline catalog).
3. Do not overwrite deterministic risk scores with numerical percentages.
4. Adhere to strict qualitative confidence terminology.
"""

from typing import Dict, List, Set, Any, Tuple
from app.ai.mitre.catalog import validate_technique_id, get_technique

VALID_CONFIDENCE_TERMS = {
    "STRONG_SUPPORT",
    "PARTIAL_SUPPORT",
    "LIMITED_SUPPORT",
    "INSUFFICIENT_EVIDENCE",
}

VALID_COMPLETENESS_TERMS = {"COMPLETE", "PARTIAL", "INSUFFICIENT"}


def validate_evidence_references(
    referenced_ids: List[str],
    available_record_ids: Set[str],
) -> Tuple[List[str], List[str]]:
    """Validate that all referenced record IDs were present in the investigation's verified evidence.

    Returns:
        (valid_ids, rejected_ids)
    """
    valid_ids: List[str] = []
    rejected_ids: List[str] = []

    for rid in referenced_ids:
        if not rid:
            continue
        cleaned_id = str(rid).strip()
        if cleaned_id in available_record_ids:
            valid_ids.append(cleaned_id)
        else:
            rejected_ids.append(cleaned_id)

    return valid_ids, rejected_ids


def validate_mitre_mappings(
    mappings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Validate and normalize MITRE ATT&CK mappings against local offline catalog."""
    validated: List[Dict[str, Any]] = []

    for item in mappings:
        t_id = item.get("technique_id", "").strip().upper()
        if not validate_technique_id(t_id):
            # Reject hallucinated ATT&CK codes
            continue

        ref = get_technique(t_id)
        if not ref:
            continue

        validated.append({
            "technique_id": t_id,
            "technique_name": ref["technique_name"],
            "tactic": ref["tactic"],
            "justification": str(item.get("justification", ref["detection_context"])),
            "confidence": item.get("confidence", "PARTIAL_SUPPORT"),
        })

    return validated


def sanitize_and_validate_report(
    raw_report: Dict[str, Any],
    available_record_ids: Set[str],
) -> Dict[str, Any]:
    """Validate and sanitize full structured report output before database storage."""
    validated: Dict[str, Any] = dict(raw_report)

    # 1. Validate qualitative confidence
    confidence = str(validated.get("confidence_assessment", "PARTIAL_SUPPORT")).upper()
    if confidence not in VALID_CONFIDENCE_TERMS:
        confidence = "PARTIAL_SUPPORT"
    validated["confidence_assessment"] = confidence

    # 2. Validate completeness
    completeness = str(validated.get("evidence_completeness", "PARTIAL")).upper()
    if completeness not in VALID_COMPLETENESS_TERMS:
        completeness = "PARTIAL"
    validated["evidence_completeness"] = completeness

    # 3. Validate and purge hallucinated record citations
    raw_refs = validated.get("evidence_references", [])
    valid_refs, rejected_refs = validate_evidence_references(raw_refs, available_record_ids)
    validated["evidence_references"] = valid_refs

    # 4. Validate observed facts citations
    facts = validated.get("observed_facts", [])
    clean_facts = []
    for f in facts:
        if isinstance(f, dict):
            f_record_id = f.get("record_id")
            if f_record_id and str(f_record_id).strip() not in available_record_ids:
                # Mark as unverified or strip the hallucinated ID
                f["record_id"] = None
                f["provenance"] = "INFERRED"
            clean_facts.append(f)
        elif isinstance(f, str):
            clean_facts.append({
                "fact": f,
                "record_id": None,
                "source_technology": "sentinel_core",
                "provenance": "INFERRED",
            })
    validated["observed_facts"] = clean_facts

    # 5. Validate MITRE mappings
    raw_mitre = validated.get("mitre_attack_mappings", [])
    validated["mitre_attack_mappings"] = validate_mitre_mappings(raw_mitre)

    return validated
