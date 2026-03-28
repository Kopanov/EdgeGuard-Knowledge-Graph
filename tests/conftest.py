"""
Pytest configuration — adds src/ to sys.path so tests can import project modules
without needing an installed package.
"""

import os
import sys

import pytest

# Standalone scripts moved from src/ — not pytest-compatible (call APIs directly)
collect_ignore = [
    "test_otx_collector.py",
    "test_enrichment.py",
    "test_resilmesh_schema.py",
]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set before any test module imports `collectors.*` (config.py requires these at import).
if not os.getenv("NEO4J_PASSWORD"):
    os.environ["NEO4J_PASSWORD"] = "pytest-dummy-neo4j-password"
if not os.getenv("MISP_API_KEY"):
    os.environ["MISP_API_KEY"] = "pytest-dummy-misp-key"


@pytest.fixture(autouse=True)
def _edgeguard_required_env(monkeypatch):
    """Re-apply if a test clears env vars."""
    if not os.getenv("NEO4J_PASSWORD"):
        monkeypatch.setenv("NEO4J_PASSWORD", "pytest-dummy-neo4j-password")
    if not os.getenv("MISP_API_KEY"):
        monkeypatch.setenv("MISP_API_KEY", "pytest-dummy-misp-key")
