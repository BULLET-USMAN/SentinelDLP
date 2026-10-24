"""Detection Rules Registry and Implementations for SentinelDLP (Phase 3).

Contains version-controlled detection rules for:
- Personally Identifiable Information (Email, PK Phone, PK CNIC)
- Credentials & Secrets (Private Keys, API Tokens, Hardcoded Passwords, Connection Strings)
- Financial Information (Payment Cards with Luhn check, IBAN with MOD-97 check, Financial Markers)
- Confidential Document Labels
"""

from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Callable, Dict, List, Optional, Set, Tuple
from app.detection.validators import (
    is_valid_email,
    is_valid_pk_phone,
    validate_cnic,
    validate_iban,
    validate_luhn,
)


class DetectionCategory(str, Enum):
    """Broad sensitive data categories."""

    PII = "Personal Information"
    CREDENTIALS = "Credentials & Secrets"
    FINANCIAL = "Financial Data"
    DOCUMENT_LABEL = "Confidential Document Markers"


class ConfidenceLevel(str, Enum):
    """Evidence-based confidence tiers."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SensitivityLevel(str, Enum):
    """Defensive classification tiers."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class RuleMatchResult:
    """Result of evaluating a specific detection rule on content."""

    rule_id: str
    category: DetectionCategory
    confidence: ConfidenceLevel
    occurrence_count: int
    suggested_classification: SensitivityLevel
    rule_name: str = ""
    rule_version: str = "1.0.0"


# Known development passwords and placeholders explicitly ignored
IGNORED_PASSWORDS: Set[str] = {
    "password",
    "sentinel_secure_dev_password",
    "changeme",
    "your_password",
    "secret",
    "placeholder",
    "admin",
    "root",
    "123456",
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to measure randomness in candidate tokens."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_calculate_shannon_entropy = calculate_shannon_entropy


# =============================================================================
# Detectors
# =============================================================================


def detect_emails(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect valid, non-placeholder email addresses."""
    # Fast regex match
    pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    matches = re.findall(pattern, text)
    valid_count = sum(1 for m in matches if is_valid_email(m))
    confidence = ConfidenceLevel.HIGH if valid_count > 0 else ConfidenceLevel.LOW
    return valid_count, confidence


def detect_pk_phones(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect Pakistani phone numbers (+92-3XX-XXXXXXX, 03XXXXXXXXX)."""
    # Matches patterns like +92 300 1234567, +92-300-1234567, 03001234567
    pattern = r"(?:\+92|0092|0)[\s-]?3\d{2}[\s-]?\d{7}\b"
    matches = re.findall(pattern, text)
    valid_count = sum(1 for m in matches if is_valid_pk_phone(m))
    return valid_count, ConfidenceLevel.HIGH


def detect_pk_cnic(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect Pakistani CNIC identifiers (XXXXX-XXXXXXX-X)."""
    pattern = r"\b\d{5}-\d{7}-\d{1}\b"
    matches = re.findall(pattern, text)
    valid_count = sum(1 for m in matches if validate_cnic(m))
    return valid_count, ConfidenceLevel.HIGH


def detect_private_keys(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect private key headers (RSA, EC, OPENSSH, PGP)."""
    pattern = r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    matches = re.findall(pattern, text)
    return len(matches), ConfidenceLevel.HIGH


def detect_api_tokens(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect provider-specific API tokens (AWS, GitHub, Slack, JWT)."""
    count = 0
    # AWS Access Key ID (AKIA...)
    count += len(re.findall(r"\bAKIA[0-9A-Z]{16}\b", text))
    # GitHub Personal Access Token (ghp_, gho_, ghu_, ghs_, ghr_)
    count += len(re.findall(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b", text))
    # Slack Token (xox[baprs]-...)
    count += len(re.findall(r"\bxox[baprs]-[0-9a-zA-Z-]{24,}\b", text))
    # Standard 3-part JSON Web Token (JWT)
    count += len(re.findall(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text))

    return count, ConfidenceLevel.HIGH


def detect_connection_strings(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect database connection strings with embedded credentials."""
    pattern = r"\b(?:postgresql|postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]{4,}@[a-zA-Z0-9_\-\.]+"
    matches = re.findall(pattern, text)
    # Filter out local dev strings like sentinel_secure_dev_password
    valid_matches = [m for m in matches if "sentinel_secure_dev_password" not in m]
    return len(valid_matches), ConfidenceLevel.HIGH


def detect_hardcoded_passwords(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect hardcoded password assignments in source code or configuration files."""
    # Look for variable assignments: password = "...", db_pass: '...', secret_pass = "..."
    pattern = r"""(?i)\b(?:[a-z0-9_]*(?:password|passwd|api_secret|admin_pass)[a-z0-9_]*)\s*[:=]\s*["']([^"'\r\n]{6,64})["']"""
    matches = re.findall(pattern, text)
    valid_count = 0
    for val in matches:
        clean = val.strip().lower()
        if clean not in IGNORED_PASSWORDS and not clean.startswith("${") and not clean.startswith("env:"):
            valid_count += 1
    return valid_count, ConfidenceLevel.MEDIUM if valid_count > 0 else ConfidenceLevel.LOW


def detect_payment_cards(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect payment card numbers validated via the Luhn algorithm."""
    # Match candidate digit sequences with optional hyphens or spaces
    # 13 to 19 digits: 4XXX-XXXX-XXXX-XXXX (Visa), 5XXX... (Mastercard), 3XXX... (Amex)
    pattern = r"\b(?:\d[ -]?){13,19}\b"
    candidates = re.findall(pattern, text)
    valid_count = 0
    for c in candidates:
        if validate_luhn(c):
            valid_count += 1
    return valid_count, ConfidenceLevel.HIGH


def detect_ibans(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect International Bank Account Numbers (IBAN) validated via MOD-97 algorithm."""
    # Match candidate IBANs (e.g. PK36SCBL0000001123456701, GB82WEST12345698765432)
    pattern = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"
    candidates = re.findall(pattern, text)
    valid_count = sum(1 for c in candidates if validate_iban(c))
    return valid_count, ConfidenceLevel.HIGH


def detect_financial_markers(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect explicit financial markers and salary/payroll indicators."""
    pattern = r"(?i)\b(?:payroll(?:\s+\w+)?|salary|bank\s+account(?:\s+number)?|swift\s+code|routing\s+number|credit\s+card(?:\s+number)?|card\s+verification\s+value|cvv2?|billing\s+statement|balance\s+sheet|tax\s+return)\b"
    matches = re.findall(pattern, text)
    return len(matches), ConfidenceLevel.MEDIUM


def detect_confidential_labels(text: str) -> Tuple[int, ConfidenceLevel]:
    """Detect document classification banners and confidentiality markers."""
    pattern = r"\b(?:STRICTLY\s+CONFIDENTIAL|CONFIDENTIAL|INTERNAL\s+USE\s+ONLY|PROPRIETARY(?:\s+INFORMATION)?|RESTRICTED\s+DISTRIBUTION|DO\s+NOT\s+DISTRIBUTE)\b"
    matches = re.findall(pattern, text)
    return len(matches), ConfidenceLevel.HIGH


# =============================================================================
# Rule Catalog
# =============================================================================


@dataclass
class DetectionRule:
    """Defines a versioned, self-contained sensitive data detection rule."""

    rule_id: str
    name: str
    description: str
    category: DetectionCategory
    version: str
    default_confidence: ConfidenceLevel
    suggested_classification: SensitivityLevel
    enabled: bool
    detector_fn: Callable[[str], Tuple[int, ConfidenceLevel]]


DETECTION_RULES: List[DetectionRule] = [
    # 1. PII
    DetectionRule(
        rule_id="RULE-PII-EMAIL",
        name="Email Address Detector",
        description="Identifies valid email addresses while filtering standard domain placeholders.",
        category=DetectionCategory.PII,
        version="1.0.0",
        default_confidence=ConfidenceLevel.MEDIUM,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_emails,
    ),
    DetectionRule(
        rule_id="RULE-PII-PHONE-PK",
        name="Pakistani Mobile / Telephone Detector",
        description="Identifies Pakistani mobile and landline formats (+92-3XX-XXXXXXX, 03XXXXXXXXX).",
        category=DetectionCategory.PII,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_pk_phones,
    ),
    DetectionRule(
        rule_id="RULE-PII-CNIC-PK",
        name="Pakistani National Identity (CNIC) Detector",
        description="Identifies structurally valid Pakistani CNIC numbers (XXXXX-XXXXXXX-X).",
        category=DetectionCategory.PII,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_pk_cnic,
    ),
    # 2. Credentials
    DetectionRule(
        rule_id="RULE-CRED-PRIVATE-KEY",
        name="Cryptographic Private Key Detector",
        description="Identifies unencrypted RSA, EC, DSA, or OpenSSH private key headers.",
        category=DetectionCategory.CREDENTIALS,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.RESTRICTED,
        enabled=True,
        detector_fn=detect_private_keys,
    ),
    DetectionRule(
        rule_id="RULE-CRED-API-TOKEN",
        name="API & Access Token Detector",
        description="Identifies provider-specific access tokens (AWS Access Keys, GitHub PATs, Slack, JWT).",
        category=DetectionCategory.CREDENTIALS,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.RESTRICTED,
        enabled=True,
        detector_fn=detect_api_tokens,
    ),
    DetectionRule(
        rule_id="RULE-CRED-CONN-STRING",
        name="Database Connection String Detector",
        description="Identifies database connection URIs with embedded authentication credentials.",
        category=DetectionCategory.CREDENTIALS,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.RESTRICTED,
        enabled=True,
        detector_fn=detect_connection_strings,
    ),
    DetectionRule(
        rule_id="RULE-CRED-HARDCODED-PASSWORD",
        name="Hardcoded Password Detector",
        description="Identifies password and secret variable assignments in code and configuration.",
        category=DetectionCategory.CREDENTIALS,
        version="1.0.0",
        default_confidence=ConfidenceLevel.MEDIUM,
        suggested_classification=SensitivityLevel.RESTRICTED,
        enabled=True,
        detector_fn=detect_hardcoded_passwords,
    ),
    # 3. Financial
    DetectionRule(
        rule_id="RULE-FIN-PAYMENT-CARD",
        name="Payment Card Detector (Luhn Verified)",
        description="Identifies credit or debit card numbers validated with the Luhn algorithm.",
        category=DetectionCategory.FINANCIAL,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.RESTRICTED,
        enabled=True,
        detector_fn=detect_payment_cards,
    ),
    DetectionRule(
        rule_id="RULE-FIN-IBAN",
        name="IBAN Bank Account Detector (MOD-97 Verified)",
        description="Identifies International Bank Account Numbers validated with the MOD-97 algorithm.",
        category=DetectionCategory.FINANCIAL,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_ibans,
    ),
    DetectionRule(
        rule_id="RULE-FIN-MARKERS",
        name="Financial & Payroll Keyword Detector",
        description="Identifies salary statements, payroll summaries, and bank routing fields.",
        category=DetectionCategory.FINANCIAL,
        version="1.0.0",
        default_confidence=ConfidenceLevel.MEDIUM,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_financial_markers,
    ),
    # 4. Document Labels
    DetectionRule(
        rule_id="RULE-LABEL-CONFIDENTIAL",
        name="Confidentiality Banner & Label Detector",
        description="Identifies organizational banners like CONFIDENTIAL, RESTRICTED, or PROPRIETARY.",
        category=DetectionCategory.DOCUMENT_LABEL,
        version="1.0.0",
        default_confidence=ConfidenceLevel.HIGH,
        suggested_classification=SensitivityLevel.CONFIDENTIAL,
        enabled=True,
        detector_fn=detect_confidential_labels,
    ),
]


def evaluate_all_rules(text: str) -> List[RuleMatchResult]:
    """Evaluate all enabled detection rules on extracted text.

    Returns:
        List of RuleMatchResult for all rules with 1 or more confirmed occurrences.
    """
    if not text:
        return []

    results = []
    for rule in DETECTION_RULES:
        if not rule.enabled:
            continue

        try:
            count, confidence = rule.detector_fn(text)
            if count > 0:
                results.append(
                    RuleMatchResult(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        confidence=confidence,
                        occurrence_count=count,
                        rule_version=rule.version,
                        suggested_classification=rule.suggested_classification,
                    )
                )
        except Exception:
            # Shield scanner from regex failure or unexpected string exception
            continue

    return results
