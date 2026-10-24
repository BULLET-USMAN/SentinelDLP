"""Synthetic Test Data Generator for SentinelDLP Scanner (Phase 2).

Generates safe, fictional test files across all supported categories
for reproducible local and container scanning tests.
Zero real credentials, personal records, or malicious content.
"""

import json
from pathlib import Path
import zipfile


def generate_synthetic_samples(target_dir: Path) -> None:
    """Populate target_dir with sample files of various supported types."""
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Plain Text Documents
    (target_dir / "sample_policy.txt").write_text(
        "SentinelDLP Data Handling Policy: All company assets must be classified according to organizational data handling standards.",
        encoding="utf-8",
    )
    (target_dir / "system_audit.log").write_text(
        "2026-10-24 10:00:00 [INFO] System audit log initialized for authorized workstation test.",
        encoding="utf-8",
    )

    # 2. Structured Data
    (target_dir / "inventory_records.csv").write_text(
        "asset_id,department,sensitivity_level,assigned_user\n"
        "AST-1001,Engineering,Confidential,user_test_1@corp.local\n"
        "AST-1002,Operations,Internal,user_test_2@corp.local\n",
        encoding="utf-8",
    )

    sample_json = {
        "platform": "SentinelDLP",
        "phase": 2,
        "sample_metric": 42,
        "classification_standards": ["Public", "Internal", "Confidential", "Restricted"],
    }
    (target_dir / "config_manifest.json").write_text(json.dumps(sample_json, indent=2), encoding="utf-8")

    (target_dir / "security_metadata.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<securityPolicy>\n'
        '  <name>EndpointDefensiveStandards</name>\n'
        '  <version>2.0</version>\n'
        '</securityPolicy>\n',
        encoding="utf-8",
    )

    # 3. Source Code & Configuration
    sub_code_dir = target_dir / "code_samples"
    sub_code_dir.mkdir(exist_ok=True)

    (sub_code_dir / "analyzer.py").write_text(
        '"""Synthetic code module."""\n'
        'def evaluate_safety_boundary(metric: int) -> bool:\n'
        '    return metric > 0\n',
        encoding="utf-8",
    )

    (sub_code_dir / "client.ts").write_text(
        'export interface SecurityContext {\n'
        '  readonly authenticated: boolean;\n'
        '  readonly tokenScope: string;\n'
        '}\n',
        encoding="utf-8",
    )

    (sub_code_dir / "service.js").write_text(
        'function calculateCheckDigit(value) {\n'
        '  return value.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0) % 10;\n'
        '}\n'
        'module.exports = { calculateCheckDigit };\n',
        encoding="utf-8",
    )

    (sub_code_dir / "SecurityUtils.java").write_text(
        'public class SecurityUtils {\n'
        '    public static boolean verifyChecksum(String hash) {\n'
        '        return hash != null && hash.length() == 64;\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )

    (target_dir / ".env.example").write_text(
        "# Synthetic configuration template\n"
        "DATABASE_PORT=5432\n"
        "LOG_LEVEL=INFO\n",
        encoding="utf-8",
    )

    (target_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: sentinel-scanner-worker\n"
        "spec:\n"
        "  replicas: 1\n",
        encoding="utf-8",
    )

    (target_dir / "schema_definition.sql").write_text(
        "CREATE TABLE test_synthetic_table (\n"
        "  id VARCHAR(36) PRIMARY KEY,\n"
        "  metric_value INTEGER\n"
        ");\n",
        encoding="utf-8",
    )

    # 4. Valid Binary Formats with Magic Signatures
    # Minimal valid PDF header
    (target_dir / "corporate_spec.pdf").write_bytes(
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"
    )

    # Minimal valid 1x1 PNG
    png_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082"
    )
    (target_dir / "shield_badge.png").write_bytes(png_bytes)

    # Minimal valid JPEG header
    (target_dir / "network_diagram.jpg").write_bytes(
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
    )

    # Valid ZIP archive
    zip_path = target_dir / "audit_archive.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested_readme.txt", "Synthetic archive contents for SentinelDLP inventory.")

    # 5. Extension / Signature Discrepancy Test Files (Intentional Mismatches)
    (target_dir / "disguised_text.pdf").write_text(
        "This file claims to be a PDF by its extension, but contains plain text without a PDF header.",
        encoding="utf-8",
    )
    (target_dir / "spoofed_image.png").write_text(
        "Plain text payload pretending to be a PNG image file.",
        encoding="utf-8",
    )

    # 6. Phase 3: Synthetic Sensitive Data Files (Defensive Test Vectors)
    # PII Sample: Pakistani CNIC, Mobile Phone, and Corporate Email
    (target_dir / "customer_pii_roster.csv").write_text(
        "customer_id,full_name,cnic,contact_phone,email_address\n"
        "CUST-001,Ahmed Khan,35201-1234567-1,03001234567,ahmed.khan@corp-internal.pk\n"
        "CUST-002,Fatima Tariq,42101-7654321-3,+92-321-9876543,fatima.tariq@acme-corp.com\n",
        encoding="utf-8",
    )

    # Credentials Sample: AWS Access Key, DB Connection String, and Hardcoded Password
    (target_dir / "cloud_credentials_backup.env").write_text(
        "# Synthetic configuration with dummy credential patterns\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_URL=postgresql://dbadmin:Sup3rS3cur3P@ssw0rd!@10.0.0.15:5432/proddb\n"
        'API_SECRET_KEY="SuperSecretP@ssw0rd2026!"\n',
        encoding="utf-8",
    )

    # Private Key Sample: Synthetic RSA Key Block
    (target_dir / "server_private_key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0mYFakeKeySyntheticOnlyDoNotUse1234567890ABCDEF\n"
        "GhIjKlMnOpQrStUvWxYz0123456789+abcdefghijklmnopqrstuvwxyzABCDEF\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    # Financial Sample: Luhn-valid Card, Mod-97 Valid Pakistani IBAN, and Financial Keywords
    sample_financial = {
        "statement_period": "Q3 2026",
        "settlement_account": "PK36SCBL0000001123456702",
        "corporate_procurement_card": "4532015112830366",
        "payroll_summary": {
            "total_salary_disbursement": 8500000,
            "bonus_allocation": 1200000,
            "tax_withheld": 750000,
        },
        "balance_sheet_status": "audited",
    }
    (target_dir / "financial_audit_extract.json").write_text(
        json.dumps(sample_financial, indent=2),
        encoding="utf-8",
    )

    # Document Labels Sample: Confidentiality Marker
    (target_dir / "board_meeting_minutes.txt").write_text(
        "CONFIDENTIAL - STRICTLY FOR INTERNAL DIRECTORS ONLY\n\n"
        "Meeting Minutes: Executive Strategy & Product Roadmap\n"
        "RESTRICTED DISTRIBUTION: Any unauthorized copying, distribution, or forwarding is strictly prohibited.\n"
        "All corporate intellectual property and trade secrets discussed remain proprietary.\n",
        encoding="utf-8",
    )

    # Valid DOCX Sample with XML document structure containing sensitive markers
    docx_path = target_dir / "executive_compensation.docx"
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '  <w:body>\n'
        '    <w:p><w:r><w:t>RESTRICTED &amp; CONFIDENTIAL - EXECUTIVE SALARY &amp; COMPENSATION AUDIT</w:t></w:r></w:p>\n'
        '    <w:p><w:r><w:t>FY2026 Annual executive payroll review and pension distribution ledger.</w:t></w:r></w:p>\n'
        '  </w:body>\n'
        '</w:document>'
    )
    with zipfile.ZipFile(docx_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", doc_xml)


if __name__ == "__main__":
    import sys
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_data")
    generate_synthetic_samples(dest)
    print(f"Generated synthetic test samples in {dest.resolve()}")
