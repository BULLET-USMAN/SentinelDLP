"""Synthetic test data generator for benign, sensitive, and staging artifacts.

Generates strictly fictional, harmless test files:
- Benign baseline files (python, text, public data)
- Sensitive files with synthetic CNIC, Luhn-valid test cards, and dummy API keys
- Safe ZIP archives for staging simulation
- Zero real user data or confidential company records
"""

import os
import random
import zipfile
from pathlib import Path
from typing import List, Tuple

from app.simulation.safety import validate_sandbox_path, get_sandbox_root


def _generate_luhn_credit_card(seed: int, prefix: str = "400000") -> str:
    """Generate a 16-digit test card number that satisfies the Luhn checksum."""
    rng = random.Random(seed)
    # Generate 9 random digits after the 6-digit prefix
    middle_digits = [rng.randint(0, 9) for _ in range(9)]
    digits = [int(d) for d in prefix] + middle_digits

    # Compute checksum
    total = 0
    # Process from right to left with doubling alternating digits
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:  # In 15 digits (excluding final check digit), position 0 is doubled
            doubled = digit * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += digit

    check_digit = (10 - (total % 10)) % 10
    digits.append(check_digit)
    return "".join(str(d) for d in digits)


class SyntheticDataGenerator:
    """Creates isolated test artifacts within the simulation laboratory sandbox."""

    def __init__(self, run_id: str, seed: int = 42):
        self.run_id = run_id
        self.seed = seed
        self.rng = random.Random(seed)
        self.run_dir = get_sandbox_root() / f"run_{run_id}"
        self.created_files: List[Path] = []

    def ensure_run_dir(self) -> Path:
        """Create and validate the run directory within the sandbox."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        return validate_sandbox_path(self.run_dir)

    def create_benign_file(self, filename: str = "system_health_check.py") -> Path:
        """Create an innocuous script with zero sensitive indicators."""
        target = self.ensure_run_dir() / filename
        validated = validate_sandbox_path(target)
        content = (
            "# Benign system diagnostic utility\n"
            "import os\n"
            "import time\n\n"
            "def check_disk_space():\n"
            "    print('Disk metrics: 82% available')\n"
            "    return True\n\n"
            "if __name__ == '__main__':\n"
            "    check_disk_space()\n"
        )
        validated.write_text(content, encoding="utf-8")
        self.created_files.append(validated)
        return validated

    def create_benign_document(self, filename: str = "public_release_notes.txt") -> Path:
        """Create a benign text document."""
        target = self.ensure_run_dir() / filename
        validated = validate_sandbox_path(target)
        content = (
            "SentinelDLP Public Release Notes - Version 2.4.0\n"
            "================================================\n"
            "Features:\n"
            "- Added detection coverage metrics\n"
            "- Improved dashboard loading time\n"
            "- Standard security telemetry integration\n"
        )
        validated.write_text(content, encoding="utf-8")
        self.created_files.append(validated)
        return validated

    def create_sensitive_cnic_file(self, filename: str = "customers_cnic_export.csv") -> Path:
        """Create a file with synthetic Pakistani CNIC numbers."""
        target = self.ensure_run_dir() / filename
        validated = validate_sandbox_path(target)
        
        # Fictional Pakistani CNICs: XXXXX-XXXXXXX-X
        cnic_1 = f"{self.rng.randint(31000, 39999)}-{self.rng.randint(1000000, 9999999)}-{self.rng.randint(1, 9)}"
        cnic_2 = f"{self.rng.randint(41000, 49999)}-{self.rng.randint(1000000, 9999999)}-{self.rng.randint(1, 9)}"
        cnic_3 = f"{self.rng.randint(61000, 69999)}-{self.rng.randint(1000000, 9999999)}-{self.rng.randint(1, 9)}"

        content = (
            "id,full_name,national_identity,account_type\n"
            f"101,Tariq Mahmood,{cnic_1},PREMIUM\n"
            f"102,Ayesha Khan,{cnic_2},STANDARD\n"
            f"103,Zubair Ahmed,{cnic_3},ENTERPRISE\n"
        )
        validated.write_text(content, encoding="utf-8")
        self.created_files.append(validated)
        return validated

    def create_sensitive_financial_file(self, filename: str = "billing_transactions.json") -> Path:
        """Create a file with Luhn-valid synthetic credit card numbers."""
        target = self.ensure_run_dir() / filename
        validated = validate_sandbox_path(target)

        card_1 = _generate_luhn_credit_card(self.seed + 1, "400000")
        card_2 = _generate_luhn_credit_card(self.seed + 2, "510510")

        content = (
            "{\n"
            '  "batch_id": "SIM-TRANS-2026",\n'
            '  "transactions": [\n'
            '    {\n'
            '      "client": "Synthetic Corp",\n'
            f'      "primary_account_number": "{card_1}",\n'
            '      "exp": "12/28",\n'
            '      "amount_usd": 1250.00\n'
            '    },\n'
            '    {\n'
            '      "client": "Simulated LLC",\n'
            f'      "primary_account_number": "{card_2}",\n'
            '      "exp": "09/27",\n'
            '      "amount_usd": 450.50\n'
            '    }\n'
            "  ]\n"
            "}\n"
        )
        validated.write_text(content, encoding="utf-8")
        self.created_files.append(validated)
        return validated

    def create_sensitive_credentials_file(self, filename: str = "cloud_credentials.env") -> Path:
        """Create a file with synthetic API keys and simulated secrets."""
        target = self.ensure_run_dir() / filename
        validated = validate_sandbox_path(target)

        # Generate standard 20-character AWS Key (AKIA + 16 uppercase alphanumeric)
        suffix = "".join(self.rng.choices("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=16))
        fake_aws_key = f"AKIA{suffix}"
        fake_secret = f"{fake_aws_key}_SECRET_abcdefghijklmnopqrstuvwxyz012345"

        content = (
            "# SYNTHETIC CREDENTIAL TEST FILE\n"
            f"AWS_ACCESS_KEY_ID={fake_aws_key}\n"
            f"AWS_SECRET_ACCESS_KEY={fake_secret}\n"
            "DATABASE_PASSWORD=SuperSecretPassw0rd!2026\n"
        )
        validated.write_text(content, encoding="utf-8")
        self.created_files.append(validated)
        return validated

    def create_staging_archive(self, zip_filename: str = "staged_exfil_bundle.zip") -> Path:
        """Package sensitive files into a safe ZIP archive."""
        # Ensure underlying sensitive files exist
        csv_file = self.create_sensitive_cnic_file("sensitive_clients.csv")
        env_file = self.create_sensitive_credentials_file("api_tokens.env")

        target = self.ensure_run_dir() / zip_filename
        validated = validate_sandbox_path(target)

        with zipfile.ZipFile(validated, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(csv_file, arcname=csv_file.name)
            zf.write(env_file, arcname=env_file.name)

        self.created_files.append(validated)
        return validated

    def cleanup(self) -> int:
        """Safely remove all files and directory created for this run."""
        deleted = 0
        for f in self.created_files:
            try:
                if f.is_file():
                    f.unlink(missing_ok=True)
                    deleted += 1
            except Exception:
                pass
        
        # Finally delete run_dir if empty or via safe traversal check
        try:
            if self.run_dir.is_dir():
                import shutil
                shutil.rmtree(self.run_dir, ignore_errors=True)
                deleted += 1
        except Exception:
            pass
        return deleted
