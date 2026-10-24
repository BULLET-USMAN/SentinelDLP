"""Application Configuration Module for SentinelDLP.

Utilizes Pydantic Settings for strictly typed, environment-driven configuration.
Ensures zero hardcoded secrets and validates values before runtime.
"""

from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SentinelDLP core configuration settings."""

    # Application Metadata
    APP_NAME: str = "SentinelDLP"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = Field(default="development", description="Current execution environment")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    API_V1_PREFIX: str = "/api/v1"

    # Server Configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS Settings
    ALLOWED_ORIGINS: Union[List[str], str] = Field(
        default=["http://localhost:5173", "http://127.0.0.1:5173"],
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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Singleton settings instance
settings = Settings()
