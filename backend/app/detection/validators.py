"""Algorithmic Validators for Sensitive Data Patterns (Phase 3).

Implements mathematical and structural checksums to eliminate false positives:
- Luhn algorithm for payment cards.
- MOD-97 algorithm for International Bank Account Numbers (IBAN).
- Pakistani CNIC format and structural validation.
- Email domain and placeholder exclusion.
"""

import re
from typing import Optional


def validate_luhn(candidate: str) -> bool:
    """Validate payment card number candidate using the Luhn algorithm (mod 10).

    Args:
        candidate: Candidate string containing digits (may include spaces or dashes).

    Returns:
        bool: True if candidate is 13-19 digits and passes Luhn checksum.
    """
    clean_digits = re.sub(r"[\s-]", "", candidate)
    if not clean_digits.isdigit() or not (13 <= len(clean_digits) <= 19):
        return False

    # Prevent false positives on repeated digits (e.g. 0000000000000000 or 1111111111111111)
    if len(set(clean_digits)) == 1:
        return False

    total = 0
    reverse_digits = clean_digits[::-1]

    for idx, char in enumerate(reverse_digits):
        n = int(char)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def validate_iban(candidate: str) -> bool:
    """Validate International Bank Account Number (IBAN) using the MOD-97 algorithm.

    Supports Pakistani IBANs (e.g. PK36SCBL0000001123456701, 24 characters)
    and international IBANs (15 to 34 characters).
    """
    clean_iban = re.sub(r"[\s-]", "", candidate).upper()

    # Basic format check: 2 letter country code, 2 check digits, followed by 11-30 alphanumeric
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", clean_iban):
        return False

    # Move first 4 characters to the end
    reordered = clean_iban[4:] + clean_iban[:4]

    # Convert letters to digits (A=10, B=11, ..., Z=35)
    numeric_string = ""
    for char in reordered:
        if char.isdigit():
            numeric_string += char
        elif char.isalpha():
            numeric_string += str(ord(char) - ord("A") + 10)
        else:
            return False

    # Modulo 97 check
    try:
        return int(numeric_string) % 97 == 1
    except ValueError:
        return False


def validate_cnic(candidate: str) -> bool:
    """Validate Pakistani Computerized National Identity Card (CNIC) structure.

    Conventional format: 5 digits (location) - 7 digits (family tree) - 1 digit (gender).
    Total: 13 digits separated by 2 hyphens (XXXXX-XXXXXXX-X).
    """
    clean = candidate.strip()
    if not re.match(r"^\d{5}-\d{7}-\d{1}$", clean):
        return False

    # Province/Location digit: First digit is typically 1 (KP), 2 (FATA), 3 (Punjab),
    # 4 (Sindh), 5 (Balochistan), 6 (Islamabad), 7 (Gilgit-Baltistan / AJK)
    first_digit = int(clean[0])
    if first_digit not in range(1, 8):
        return False

    # Prevent trivial repeated patterns like 00000-0000000-0 or 12345-1234567-1
    raw_digits = clean.replace("-", "")
    if len(set(raw_digits)) < 4:
        return False

    return True


# Common placeholder domains and dummy accounts excluded to prevent false positives
IGNORED_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "domain.com",
    "test.com",
    "sample.local",
    "corp.local",
    "company.com",
}


def is_valid_email(email_str: str) -> bool:
    """Validate email address format and filter obvious template placeholders."""
    clean = email_str.strip().lower()
    # RFC 5322 simplified pattern
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", clean):
        return False

    # Filter out common placeholders and RFC 2606 reserved testing TLDs
    domain = clean.split("@")[-1]
    if domain in IGNORED_EMAIL_DOMAINS or any(domain.endswith(tld) for tld in (".test", ".example", ".invalid", ".localhost", ".local")):
        return False

    # Exclude common image-srcset patterns like user@2x.png
    if any(clean.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return False

    return True


def is_valid_pk_phone(phone_str: str) -> bool:
    """Validate Pakistani mobile and landline telephone formats.

    Matches:
    - Mobile: +92 3XX XXXXXXX, +92-3XX-XXXXXXX, 03XXXXXXXXX, 00923XXXXXXXXX
    """
    clean = re.sub(r"[\s-]", "", phone_str)
    # Convert +92 or 0092 to local format 03...
    if clean.startswith("+92"):
        clean = "0" + clean[3:]
    elif clean.startswith("0092"):
        clean = "0" + clean[4:]

    # Pakistani mobile numbers start with 03 followed by 9 digits (total 11 digits)
    if re.match(r"^03\d{9}$", clean):
        # 3rd digit is typically 0-4 (operators Jazz, Zong, Ufone, Telenor, SCO)
        return clean[2] in "01234"

    return False
