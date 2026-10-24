"""Unit Tests for Detection Rules and Validators in SentinelDLP (Phase 3).

Validates:
- Algorithmic validators (Luhn, IBAN, Pakistani CNIC, Pakistani Phone, Email)
- Shannon entropy calculator
- Pattern matching across PII, Credentials, Financial data, and Document Labels
"""

import pytest
from app.detection.rules import (
    ConfidenceLevel,
    DetectionCategory,
    SensitivityLevel,
    calculate_shannon_entropy,
    evaluate_all_rules,
)
from app.detection.validators import (
    is_valid_email,
    is_valid_pk_phone,
    validate_cnic,
    validate_iban,
    validate_luhn,
)


def test_validate_luhn_algorithm() -> None:
    """Verify Luhn mod-10 algorithm for valid and invalid card numbers."""
    # Valid Visa test number
    assert validate_luhn("4532015112830366") is True
    # Invalid card number (checksum altered)
    assert validate_luhn("4532015112830367") is False
    # Non-digit or too short
    assert validate_luhn("4532") is False
    assert validate_luhn("4532abcd12345678") is False


def test_validate_pakistani_iban() -> None:
    """Verify IBAN MOD-97 checksum calculation for Pakistani accounts."""
    # Valid Standard Chartered PK IBAN
    assert validate_iban("PK36SCBL0000001123456702") is True
    # Valid with whitespace
    assert validate_iban("PK36 SCBL 0000 0011 2345 6702") is True
    # Corrupted check digits
    assert validate_iban("PK99SCBL0000001123456702") is False
    # Invalid length
    assert validate_iban("PK36SCBL123") is False


def test_validate_pakistani_cnic() -> None:
    """Verify Pakistani CNIC format (5 digits - 7 digits - 1 digit)."""
    assert validate_cnic("35201-1234567-1") is True
    assert validate_cnic("42101-7654321-3") is True
    # Invalid: province code 0
    assert validate_cnic("05201-1234567-1") is False
    # Invalid: missing hyphens or wrong group counts
    assert validate_cnic("3520112345671") is False
    assert validate_cnic("3520-1234567-1") is False


def test_validate_pakistani_phone() -> None:
    """Verify Pakistani mobile phone formats."""
    assert is_valid_pk_phone("03001234567") is True
    assert is_valid_pk_phone("+923001234567") is True
    assert is_valid_pk_phone("+92-321-9876543") is True
    # Invalid operator code (035X does not exist)
    assert is_valid_pk_phone("03551234567") is False
    # Landline or international number
    assert is_valid_pk_phone("0511234567") is False


def test_email_validation_and_placeholder_exclusion() -> None:
    """Verify email format validation and exclusion of mock/example domains."""
    assert is_valid_email("security.auditor@corporation.com") is True
    assert is_valid_email("admin_ops@domain.pk") is True
    # Placeholders should be excluded to reduce false positives
    assert is_valid_email("user@example.com") is False
    assert is_valid_email("test@domain.test") is False
    assert is_valid_email("placeholder@yourcompany.local") is False


def test_shannon_entropy_calculation() -> None:
    """Verify Shannon entropy calculation for random vs uniform strings."""
    # Low entropy (repetitive)
    low_ent = calculate_shannon_entropy("AAAAAAAAAAAAAAAAAAAA")
    assert low_ent == 0.0
    # High entropy (cryptographic key / random hex string)
    high_ent = calculate_shannon_entropy("e8f7a93c4b12d56e0fa8b291c3d4e5f6")
    assert high_ent > 3.0


def test_evaluate_all_rules_on_pii() -> None:
    """Verify PII rules detect CNIC, email, and Pakistani phone."""
    text = (
        "Employee records:\n"
        "Name: Muhammad Ali\n"
        "CNIC: 35202-9876543-5\n"
        "Contact: +92-333-1122334\n"
        "Email: muhammad.ali@enterprise-pk.com\n"
    )
    findings = evaluate_all_rules(text)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-PII-CNIC-PK" in rule_ids
    assert "RULE-PII-PHONE-PK" in rule_ids
    assert "RULE-PII-EMAIL" in rule_ids


def test_evaluate_all_rules_on_credentials() -> None:
    """Verify credentials rules detect AWS keys, private keys, connection strings, and passwords."""
    text = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_URL=postgresql://usr:MySecr3tP@ss!@localhost:5432/db\n"
        "ADMIN_PASS=\"SuperS3cur3P@ssw0rd!\"\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0mYFakeKeySyntheticOnlyDoNotUse1234567890ABCDEF\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    findings = evaluate_all_rules(text)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-CRED-API-TOKEN" in rule_ids
    assert "RULE-CRED-CONN-STRING" in rule_ids
    assert "RULE-CRED-HARDCODED-PASSWORD" in rule_ids
    assert "RULE-CRED-PRIVATE-KEY" in rule_ids


def test_evaluate_all_rules_on_financial_and_markers() -> None:
    """Verify financial and confidentiality label rules."""
    text = (
        "RESTRICTED AND CONFIDENTIAL\n"
        "Payment reconciliation for Card: 4532015112830366\n"
        "Settlement Account: PK36SCBL0000001123456702\n"
        "Executive annual salary and payroll disbursement audit.\n"
    )
    findings = evaluate_all_rules(text)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-FIN-PAYMENT-CARD" in rule_ids
    assert "RULE-FIN-IBAN" in rule_ids
    assert "RULE-FIN-MARKERS" in rule_ids
    assert "RULE-LABEL-CONFIDENTIAL" in rule_ids
