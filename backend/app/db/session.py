"""Database Session and Connection Management for SentinelDLP.

Configures the SQLAlchemy engine, session maker, and connectivity health probe.
Ensures connection pool stability and secure credential isolation.
"""

import time
from typing import Generator, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import logger

# Construct engine with pool pre-ping and timeout settings
connect_args = {}
if settings.DATABASE_URL.startswith("postgresql"):
    connect_args["connect_timeout"] = settings.DB_TIMEOUT_SECONDS

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connectivity() -> Tuple[bool, str, float]:
    """Execute a lightweight probe (SELECT 1) to verify database connectivity.

    Returns:
        Tuple of (is_connected: bool, message: str, latency_ms: float)
    """
    start_time = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        latency = (time.perf_counter() - start_time) * 1000.0
        return True, "Database operational", round(latency, 2)
    except SQLAlchemyError as err:
        latency = (time.perf_counter() - start_time) * 1000.0
        logger.error(
            "Database connectivity check failed",
            extra={"component": "database", "event": "health_check_failure", "latency_ms": round(latency, 2)},
        )
        return False, "Database connection failure or timeout", round(latency, 2)
    except Exception as err:
        latency = (time.perf_counter() - start_time) * 1000.0
        logger.error(
            "Unexpected error during database connectivity probe",
            extra={"component": "database", "event": "probe_exception"},
        )
        return False, "Database service unreachable", round(latency, 2)
