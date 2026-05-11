"""
Pytest configuration and fixtures.
Adds project root to sys.path so backend module can be imported.
Provides fixtures for isolated testing with centralized test database directory.
"""

import sys
import os
import shutil
from pathlib import Path
import pytest


# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


# Centralized test database directory
TEST_DB_DIR = Path(project_root) / ".pytest-db"


@pytest.fixture(scope="session", autouse=True)
def setup_test_db_dir():
    """Create test database directory and clean up after all tests.
    
    All test databases are stored in a single .pytest-db directory
    for easier management and cleanup.
    """
    TEST_DB_DIR.mkdir(exist_ok=True)
    yield
    # Clean up entire directory after all tests complete
    if TEST_DB_DIR.exists():
        shutil.rmtree(TEST_DB_DIR, ignore_errors=True)


@pytest.fixture
def temp_db():
    """Provide a temporary database file in the centralized test directory."""
    import uuid
    db_path = TEST_DB_DIR / f"test_{uuid.uuid4().hex[:8]}.db"
    yield str(db_path)
    # Individual cleanup (redundant but safe since session cleanup removes dir)
    try:
        db_path.unlink()
    except Exception:
        pass


@pytest.fixture
def isolated_event_store(temp_db, monkeypatch):
    """Provide an isolated EventStore with temp database for each test."""
    from backend.events.event_store import EventStore
    store = EventStore(max_events=100, db_path=temp_db)
    # Also patch the global instance to use this temp store for imports in test code
    monkeypatch.setattr("backend.events.event_store._event_store", store)
    return store
