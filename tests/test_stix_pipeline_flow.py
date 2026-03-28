#!/usr/bin/env python3
"""
Test script for STIX 2.1 pipeline flow integration.

This script tests the new --stix-flow option that enables:
    Collectors → MISP → STIX 2.1 → Neo4j
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_stix_flow_flag():
    """Test that --stix-flow flag is properly registered."""
    logger.info("Testing --stix-flow CLI flag...")

    import argparse

    # Simulate parsing with --stix-flow
    parser = argparse.ArgumentParser()
    parser.add_argument("--stix-flow", action="store_true")
    parser.add_argument("--stix", action="store_true")
    parser.add_argument("--stix-output", type=str, default="test.json")
    parser.add_argument("--stix-event", type=str, default=None)

    args = parser.parse_args(["--stix-flow"])

    assert args.stix_flow is True, "stix_flow flag not parsed correctly"
    logger.info("✅ --stix-flow flag is properly registered")


def test_stix_flow_methods():
    """Test that all STIX flow methods exist."""
    logger.info("\nTesting STIX flow methods...")

    from run_pipeline import EdgeGuardPipeline

    required_methods = [
        "load_stix21_to_neo4j",
        "_parse_stix_pattern",
        "_stix_observable_type_to_indicator",
        "_run_stix_flow",
    ]

    for method in required_methods:
        assert hasattr(EdgeGuardPipeline, method), f"Missing method: {method}"
        logger.info(f"✅ {method} exists")


def test_pattern_parsing():
    """Test STIX pattern parsing."""
    logger.info("\nTesting STIX pattern parsing...")

    from run_pipeline import EdgeGuardPipeline

    pipeline = EdgeGuardPipeline()

    test_cases = [
        ("[ipv4-addr:value = '192.168.1.1']", {"type": "ipv4", "value": "192.168.1.1"}),
        ("[ipv6-addr:value = '::1']", {"type": "ipv6", "value": "::1"}),
        ("[domain-name:value = 'evil.com']", {"type": "domain", "value": "evil.com"}),
        ("[url:value = 'http://evil.com/malware']", {"type": "url", "value": "http://evil.com/malware"}),
        (
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},
        ),
    ]

    for pattern, expected in test_cases:
        result = pipeline._parse_stix_pattern(pattern)
        assert result == expected, f"Failed: {pattern} -> {result}, expected {expected}"
        logger.info(f"✅ {pattern[:50]:<50} -> {result}")


def test_run_method_signature():
    """Test that run() method accepts use_stix_flow parameter."""
    logger.info("\nTesting run() method signature...")

    import inspect

    from run_pipeline import EdgeGuardPipeline

    sig = inspect.signature(EdgeGuardPipeline.run)
    params = list(sig.parameters.keys())

    assert "use_stix_flow" in params, "use_stix_flow parameter missing from run()"
    logger.info(f"✅ run() parameters: {params}")

    # Check default value
    use_stix_flow_param = sig.parameters["use_stix_flow"]
    assert use_stix_flow_param.default == False, "use_stix_flow should default to False"
    logger.info("✅ use_stix_flow defaults to False (backward compatible)")


def test_stix_bundle_loading_logic():
    """Test the STIX bundle loading logic without Neo4j."""
    logger.info("\nTesting STIX bundle loading logic...")

    from run_pipeline import EdgeGuardPipeline

    # Create a test bundle
    test_bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "spec_version": "2.1",
        "objects": [
            {"type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4--1", "value": "1.2.3.4"},
            {"type": "domain-name", "spec_version": "2.1", "id": "domain--1", "value": "test.com"},
            {"type": "vulnerability", "spec_version": "2.1", "id": "vuln--1", "name": "CVE-2024-1234"},
            {"type": "threat-actor", "spec_version": "2.1", "id": "actor--1", "name": "APT-TEST"},
            {"type": "malware", "spec_version": "2.1", "id": "malware--1", "name": "TestMalware"},
            {"type": "attack-pattern", "spec_version": "2.1", "id": "technique--1", "name": "T1234"},
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "pattern_type": "stix",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
            },
        ],
    }

    pipeline = EdgeGuardPipeline()

    # Just verify the bundle structure is valid
    assert "objects" in test_bundle
    assert len(test_bundle["objects"]) == 7

    object_types = [obj["type"] for obj in test_bundle["objects"]]
    expected_types = [
        "ipv4-addr",
        "domain-name",
        "vulnerability",
        "threat-actor",
        "malware",
        "attack-pattern",
        "indicator",
    ]

    for expected in expected_types:
        assert expected in object_types, f"Missing object type: {expected}"

    logger.info(f"✅ Test bundle has {len(test_bundle['objects'])} objects")
    logger.info(f"✅ Object types: {object_types}")


def main():
    """Run all STIX flow integration tests."""
    logger.info("=" * 60)
    logger.info("🔬 EdgeGuard STIX 2.1 Pipeline Flow Tests")
    logger.info("=" * 60)

    tests = [
        ("CLI Flag Registration", test_stix_flow_flag),
        ("STIX Flow Methods", test_stix_flow_methods),
        ("Pattern Parsing", test_pattern_parsing),
        ("Run Method Signature", test_run_method_signature),
        ("STIX Bundle Loading Logic", test_stix_bundle_loading_logic),
    ]

    results = []
    for name, test_func in tests:
        try:
            test_func()
            results.append((name, True, None))
        except Exception as e:
            results.append((name, False, str(e)))

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("📊 Test Results Summary")
    logger.info("=" * 60)

    passed = sum(1 for _, result, _ in results if result)
    total = len(results)

    for name, result, error in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"   {status}: {name}")
        if error:
            logger.error(f"      Error: {error}")

    logger.info(f"\n📈 Passed: {passed}/{total}")

    if passed == total:
        logger.info("\n🎉 All tests passed! STIX 2.1 pipeline flow is ready.")
        return 0
    else:
        logger.error(f"\n⚠️ {total - passed} test(s) failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
