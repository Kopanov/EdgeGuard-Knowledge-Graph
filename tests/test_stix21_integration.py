#!/usr/bin/env python3
"""
Test script for STIX 2.1 integration in EdgeGuard pipeline.

This script tests:
1. STIX library availability
2. PyMISP to_stix2() functionality
3. The STIX flow methods of the pipeline (MISP → STIX 2.1 → Neo4j)
"""

import logging
import os
import sys

import pytest

# Add src to path (this file lives in tests/)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from stub_cleanup import clear_graphql_api_magicmock_stubs


@pytest.fixture(autouse=True)
def _clean_stubs():
    """Clean GraphQL API stubs before each test to avoid MagicMock interference."""
    clear_graphql_api_magicmock_stubs()


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_stix_library():
    """Test if stix2 library is available."""
    logger.info("Testing STIX 2.1 library availability...")
    import stix2

    logger.info(f"✅ stix2 library version: {stix2.__version__}")
    assert hasattr(stix2, "__version__")


def test_pymisp_stix_conversion():
    """Test PyMISP STIX conversion with a mock event."""
    logger.info("\nTesting PyMISP to_stix2() conversion...")

    from pymisp import MISPEvent

    # Create a mock MISP event
    event = MISPEvent()
    event.info = "Test EdgeGuard Event"
    event.distribution = 0

    # PyMISP 2.5+: add_attribute(type, value, **kwargs)
    event.add_attribute("ip-dst", "192.168.1.100", comment="Test malicious IP")
    event.add_attribute("domain", "evil.example.com", comment="Test malicious domain")

    logger.info(f"✅ Created mock MISP event with {len(event.attributes)} attributes")

    if not hasattr(event, "to_stix2"):
        pytest.skip("PyMISP MISPEvent.to_stix2() not available in this PyMISP version")
    stix_objects = event.to_stix2()
    logger.info(f"✅ PyMISP to_stix2() returned {len(stix_objects)} STIX objects")
    assert len(stix_objects) >= 1

    obj = stix_objects[0]
    if hasattr(obj, "serialize"):
        logger.info(f"   First object type: {obj.type}")
        logger.info(f"   First object ID: {obj.id}")


def test_pipeline_stix_integration():
    """Test the pipeline STIX integration imports."""
    logger.info("\nTesting pipeline STIX integration...")

    from run_pipeline import STIX_AVAILABLE, EdgeGuardPipeline

    assert STIX_AVAILABLE, "STIX integration must be available (stix2 installed)"
    logger.info("✅ STIX integration available in pipeline")

    for method in ("load_stix21_to_neo4j", "_run_stix_flow"):
        assert hasattr(EdgeGuardPipeline, method), f"EdgeGuardPipeline.{method} missing"
        logger.info(f"✅ EdgeGuardPipeline.{method}() available")
    # The MISP-event STIX file export is removed; the outward STIX surface is GET /stix/export.
    for method in ("export_to_stix21", "export_single_event_to_stix21"):
        assert not hasattr(EdgeGuardPipeline, method), f"EdgeGuardPipeline.{method} is removed"


def test_misp_to_neo4j_stix_conversion():
    """Test the STIX conversion in run_misp_to_neo4j module."""
    logger.info("\nTesting run_misp_to_neo4j STIX conversion...")

    from run_misp_to_neo4j import MISPToNeo4jSync

    assert hasattr(MISPToNeo4jSync, "convert_to_stix21"), "MISPToNeo4jSync.convert_to_stix21 missing"
    logger.info("✅ MISPToNeo4jSync.convert_to_stix21() available")
    assert hasattr(MISPToNeo4jSync, "fetch_stix21_from_misp"), "MISPToNeo4jSync.fetch_stix21_from_misp missing"
    logger.info("✅ MISPToNeo4jSync.fetch_stix21_from_misp() available")


def main():
    """Run STIX tests via pytest (CLI compatibility)."""
    import pytest

    logger.info("=" * 60)
    logger.info("🔬 EdgeGuard STIX 2.1 Integration Tests")
    logger.info("=" * 60)
    return pytest.main(
        [
            __file__,
            "-v",
            "--tb=short",
            "-k",
            "test_stix_library or test_pymisp_stix_conversion "
            "or test_pipeline_stix_integration or test_misp_to_neo4j_stix_conversion",
        ]
    )


if __name__ == "__main__":
    sys.exit(main())
