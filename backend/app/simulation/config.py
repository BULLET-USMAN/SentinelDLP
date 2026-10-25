"""Configuration settings and boundaries for the Cyberattack Simulation Lab."""

import os
from pathlib import Path
from pydantic import BaseModel, Field


class SimulationSettings(BaseModel):
    """Safety and execution parameters for security scenario testing."""

    # Dedicated isolated working directory for generated artifacts
    simulation_root_name: str = "simulation_lab"
    
    # Maximum limits for safety
    max_files_per_run: int = 50
    max_bytes_per_run: int = 50 * 1024 * 1024  # 50 MB
    execution_timeout_seconds: int = 60
    default_seed: int = 42

    # Cleanup behavior
    auto_cleanup_default: bool = True
    preserve_reports: bool = True

    # Production safety guard
    allow_production_simulation: bool = Field(
        default=False,
        description="Explicit override permitting cyberattack simulations in production environment",
    )

    @property
    def simulation_dir_path(self) -> Path:
        """Resolve absolute path to sample_data/simulation_lab."""
        # Find project root (SentinelDLP)
        base = Path(__file__).resolve().parent.parent.parent.parent
        sim_dir = base / "sample_data" / self.simulation_root_name
        return sim_dir


simulation_settings = SimulationSettings()
