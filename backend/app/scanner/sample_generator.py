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


if __name__ == "__main__":
    import sys
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_data")
    generate_synthetic_samples(dest)
    print(f"Generated synthetic test samples in {dest.resolve()}")
