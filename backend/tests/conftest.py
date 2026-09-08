"""Shared pytest fixtures. Sets DATABASE_URL/RAW_EMAIL_DIR to isolated temp
locations *before* any app.* module is imported, since app/config.py and
app/db.py both read settings and create the engine at import time."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

_TEST_DB_FILE = Path(tempfile.gettempdir()) / "sih26106_test.db"
_TEST_RAW_DIR = Path(tempfile.gettempdir()) / "sih26106_test_raw"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_FILE.as_posix()}"
os.environ["RAW_EMAIL_DIR"] = str(_TEST_RAW_DIR)

SAMPLE_EMAILS_DIR = Path(__file__).parent.parent.parent / "sample_emails"


@pytest.fixture
def load_eml():
    def _load(filename: str) -> bytes:
        return (SAMPLE_EMAILS_DIR / filename).read_bytes()

    return _load


@pytest.fixture(scope="session", autouse=True)
def _test_db():
    """Deletes and re-initializes the test DB exactly once per session — SQLite
    on Windows keeps the file locked for the life of the shared engine, so
    deleting it between individual tests (as a function-scoped fixture would)
    fails with a PermissionError. Tests each assert properties of the data they
    create, not global emptiness, so a DB shared across the session is fine."""
    from app.db import init_db

    if _TEST_DB_FILE.exists():
        _TEST_DB_FILE.unlink()
    init_db()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
