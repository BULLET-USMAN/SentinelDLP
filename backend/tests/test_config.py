"""Configuration Validation Tests for SentinelDLP."""

from app.core.config import Settings


def test_settings_defaults() -> None:
    """Verify safe default settings values."""
    config = Settings()
    assert config.APP_NAME == "SentinelDLP"
    assert config.BACKEND_PORT == 8000
    assert config.DB_TIMEOUT_SECONDS == 5
    assert isinstance(config.ALLOWED_ORIGINS, list)


def test_cors_origins_parsing() -> None:
    """Verify comma-separated origin string correctly parses into a list."""
    config = Settings(ALLOWED_ORIGINS="http://localhost:3000, http://example.com")
    assert "http://localhost:3000" in config.ALLOWED_ORIGINS
    assert "http://example.com" in config.ALLOWED_ORIGINS


def test_database_url_credential_masking() -> None:
    """Verify database URL sanitization redacts password from logs."""
    config = Settings(DATABASE_URL="postgresql+psycopg2://admin:SuperSecretPass123!@db-host:5432/sentinel_db")
    sanitized = config.get_sanitized_db_url()
    assert "SuperSecretPass123!" not in sanitized
    assert "admin:***@db-host:5432/sentinel_db" in sanitized
