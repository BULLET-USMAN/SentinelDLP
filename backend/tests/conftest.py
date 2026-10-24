"""Pytest Configuration and Fixtures for SentinelDLP.

Configures test clients and isolation fixtures.
"""

import os
import sys
from typing import Generator
import pytest
from fastapi.testclient import TestClient

# Ensure backend directory is in path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app


@pytest.fixture(scope="session")
def client() -> Generator[TestClient, None, None]:
    """Test client fixture configured with the application instance."""
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client
