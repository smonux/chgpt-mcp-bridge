import os
import sys
from pathlib import Path
import pytest

# Ensure project root is on sys.path so 'import server' works
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure required env vars are set before importing server.py in tests
os.environ.setdefault("GITHUB_CLIENT_ID", "test-client-id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("EXTERNAL_HOSTNAME", "example.test")

# Optional: keep logs quieter in tests unless explicitly enabled
os.environ.setdefault("DEBUGLEVEL", "WARNING")

@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    # Each test can mutate env safely; restore after
    yield
