"""Safety containment and isolation enforcement for the simulation laboratory.

Guarantees:
- Zero write operations outside sample_data/simulation_lab.
- Path traversal rejection.
- Automated cleanup of synthetic artifacts.
- Safe file deletion without risking user or repository files.
"""

import os
import shutil
from pathlib import Path
from typing import List, Union

from app.simulation.config import simulation_settings


class SimulationSafetyViolation(Exception):
    """Raised when an operation attempts to breach the simulation sandbox."""
    pass


def get_sandbox_root() -> Path:
    """Return and guarantee existence of the isolated simulation directory."""
    root = simulation_settings.simulation_dir_path.resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def is_safe_sandbox_path(target_path: Union[str, Path]) -> bool:
    """Verify that a path is strictly inside the authorized sandbox directory."""
    sandbox_root = get_sandbox_root()
    try:
        resolved = Path(target_path).resolve()
        # Ensure target is relative to sandbox_root and not equal to or above it
        return resolved != sandbox_root and sandbox_root in resolved.parents
    except Exception:
        return False


def validate_sandbox_path(target_path: Union[str, Path]) -> Path:
    """Validate path and raise SimulationSafetyViolation if outside sandbox."""
    resolved = Path(target_path).resolve()
    sandbox_root = get_sandbox_root()
    
    if resolved == sandbox_root or sandbox_root not in resolved.parents:
        raise SimulationSafetyViolation(
            f"Access denied: Path '{target_path}' is outside isolated sandbox '{sandbox_root}'"
        )
    return resolved


def safe_cleanup_files(file_paths: List[Union[str, Path]]) -> int:
    """Safely delete a list of files created during a simulation."""
    deleted_count = 0
    for p in file_paths:
        try:
            validated = validate_sandbox_path(p)
            if validated.is_file():
                validated.unlink(missing_ok=True)
                deleted_count += 1
            elif validated.is_dir():
                shutil.rmtree(validated, ignore_errors=True)
                deleted_count += 1
        except Exception:
            continue
    return deleted_count


def safe_purge_sandbox() -> int:
    """Purge all files and subdirectories inside the sandbox root."""
    sandbox_root = get_sandbox_root()
    deleted = 0
    for item in sandbox_root.iterdir():
        try:
            if item.is_file():
                item.unlink(missing_ok=True)
                deleted += 1
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                deleted += 1
        except Exception:
            continue
    return deleted
