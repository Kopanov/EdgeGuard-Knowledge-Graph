#!/usr/bin/env python3
"""
Test script for STIX 2.1 integration in EdgeGuard pipeline.

This script tests:
1. STIX library availability
2. PyMISP to_stix2() functionality
3. STIX 2.1 bundle creation
"""

import json
import logging
import os
import sys

import pytest

# Add src to path (this file lives in tests/)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from stub_cleanup import clear_graphql_api_magicmock_stubs

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


def test_stix21_bundle_creation(tmp_path):
    """Test manual STIX 2.1 bundle creation."""
    logger.info("\nTesting STIX 2.1 bundle creation...")

    import uuid
    from datetime import datetime

    # Create a STIX 2.1 bundle manually
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": f"ipv4-addr--{uuid.uuid4()}",
                "value": "192.168.1.100",
            },
            {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": f"domain-name--{uuid.uuid4()}",
                "value": "evil.example.com",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "name": "Malicious IP Indicator",
                "pattern": "[ipv4-addr:value = '192.168.1.100']",
                "pattern_type": "stix",
                "valid_from": datetime.now().isoformat(),
            },
        ],
    }

    logger.info(f"✅ Created STIX 2.1 bundle with {len(bundle['objects'])} objects")
    logger.info(f"   Bundle ID: {bundle['id']}")
    logger.info(f"   Spec version: {bundle['spec_version']}")

    output_path = tmp_path / "test_stix21_bundle.json"
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)
    logger.info(f"✅ Test bundle saved to: {output_path}")

    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 3
    assert output_path.is_file()


def test_pipeline_stix_integration():
    """Test the pipeline STIX integration imports."""
    logger.info("\nTesting pipeline STIX integration...")

    from run_pipeline import STIX_AVAILABLE, EdgeGuardPipeline

    assert STIX_AVAILABLE, "STIX integration must be available (stix2 installed)"
    logger.info("✅ STIX integration available in pipeline")

    for method in ("export_to_stix21", "export_single_event_to_stix21"):
        assert hasattr(EdgeGuardPipeline, method), f"EdgeGuardPipeline.{method} missing"
        logger.info(f"✅ EdgeGuardPipeline.{method}() available")


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
            "test_stix_library or test_pymisp_stix_conversion or test_stix21_bundle_creation "
            "or test_pipeline_stix_integration or test_misp_to_neo4j_stix_conversion",
        ]
    )


if __name__ == "__main__":
    sys.exit(main())
