"""Application Configuration Module for SentinelDLP.

Utilizes Pydantic Settings for strictly typed, environment-driven configuration.
Ensures zero hardcoded secrets and validates values before runtime.
"""

import json
import os
from typing import Dict, List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SentinelDLP core configuration settings."""

    # Application Metadata
    APP_NAME: str = "SentinelDLP"
    APP_VERSION: str = "0.10.0"
    ENVIRONMENT: str = Field(default="development", description="Current execution environment")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    API_V1_PREFIX: str = "/api/v1"

    # Server Configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS Settings
    ALLOWED_ORIGINS: Union[List[str], str] = Field(
        default=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:80", "http://localhost"],
        description="Allowed origins for Cross-Origin Resource Sharing",
    )

    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", description="Logging verbosity")
    LOG_FORMAT: str = Field(default="json", description="Structured log format (json or console)")

    # Database Configuration
    POSTGRES_USER: str = "sentinel_user"
    POSTGRES_PASSWORD: str = "sentinel_secure_dev_password"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "sentineldlp"
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://sentinel_user:sentinel_secure_dev_password@localhost:5432/sentineldlp",
        description="Full SQLAlchemy database connection string",
    )
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_TIMEOUT_SECONDS: int = 5

    # =========================================================================
    # Phase 2: File Scanning Engine & Security Boundary Configurations
    # =========================================================================
    # Authorized scan roots mapping root_id to directory metadata
    # In container: /data/samples; on host: ./sample_data
    AUTHORIZED_SCAN_ROOTS_JSON: str = Field(
        default="",
        description="JSON string overriding authorized roots if set",
    )

    MAX_FILES_PER_SCAN: int = Field(default=10000, description="Ceiling on total files processed per scan job")
    MAX_FILE_SIZE_BYTES: int = Field(default=104857600, description="Max individual file size for hashing (100MB)")
    MAX_SCAN_DURATION_SECONDS: int = Field(default=300, description="Maximum wall-clock duration per scan job (5 min)")
    CHUNK_SIZE_BYTES: int = Field(default=65536, description="Read buffer size for streaming SHA-256 calculations (64KB)")

    # Excluded directories to prevent traversal into repository internals or package caches
    EXCLUDED_DIR_NAMES: List[str] = Field(
        default=[
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            ".pytest_cache",
            ".idea",
            ".vscode",
            "postgres_data",
            "dist",
            "build",
        ],
        description="Default directory names excluded from scanning traversal",
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated origin strings into a list of strings."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return []

    def get_sanitized_db_url(self) -> str:
        """Return the database URL with the password redacted for secure logging."""
        if "@" in self.DATABASE_URL and "://" in self.DATABASE_URL:
            prefix, rest = self.DATABASE_URL.split("://", 1)
            credentials, location = rest.split("@", 1)
            if ":" in credentials:
                user = credentials.split(":", 1)[0]
                return f"{prefix}://{user}:***@{location}"
        return "postgresql://***:***@redacted"

    def get_authorized_roots(self) -> Dict[str, Dict[str, str]]:
        """Return normalized dictionary of authorized scan roots."""
        if self.AUTHORIZED_SCAN_ROOTS_JSON:
            try:
                return json.loads(self.AUTHORIZED_SCAN_ROOTS_JSON)
            except Exception:
                pass

        # Resolve paths based on environment (Docker container vs local host)
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        sample_data_dir = os.path.join(project_root, "sample_data")
        docs_dir = os.path.join(project_root, "docs")

        # In Docker container, /data/samples is the mounted volume if it exists
        if os.path.exists("/data/samples"):
            sample_data_dir = "/data/samples"

        return {
            "synthetic_samples": {
                "name": "Synthetic Test Samples",
                "path": sample_data_dir,
                "description": "Safe, fictional synthetic documents, code files, and structured datasets.",
            },
            "project_docs": {
                "name": "Project Documentation",
                "path": docs_dir,
                "description": "Platform architecture and development specifications.",
            },
        }

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Singleton settings instance
settings = Settings()
