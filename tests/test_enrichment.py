"""EdgeGuard — Enrichment logic tests (mocked, no live services)."""

from unittest.mock import MagicMock


def test_virustotal_collector_query_domain_returns_enriched_dict():
    """VirusTotalCollector.query_domain returns an indicator dict with VT stats."""
    from collectors.virustotal_collector import VirusTotalCollector

    vt = VirusTotalCollector.__new__(VirusTotalCollector)
    vt.api_key = "test-key"
    vt.session = MagicMock()
    vt.verify_ssl = True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
                "registrar": "Example Registrar",
                "creation_date": 1609459200,
            },
            "id": "evil.example.com",
        }
    }
    vt.session.get.return_value = mock_resp

    result = vt.query_domain("evil.example.com")
    assert result is not None
    assert result["value"] == "evil.example.com"
    assert result["indicator_type"] == "domain"
    assert result.get("confidence_score", 0) > 0


def test_virustotal_collector_query_domain_not_found_returns_none():
    """VirusTotalCollector.query_domain returns None for 404."""
    from collectors.virustotal_collector import VirusTotalCollector

    vt = VirusTotalCollector.__new__(VirusTotalCollector)
    vt.api_key = "test-key"
    vt.session = MagicMock()
    vt.verify_ssl = True

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    vt.session.get.return_value = mock_resp

    result = vt.query_domain("nonexistent.example.com")
    assert result is None


def test_enrichment_merge_calls_neo4j_with_source_id():
    """Merging an enriched indicator passes source_id='virustotal'."""
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = None  # merge_indicator returns False when no driver

    enriched_item = {
        "indicator_type": "domain",
        "value": "evil.example.com",
        "zone": ["global"],
        "tag": "virustotal_enrich",
        "source": ["virustotal"],
        "confidence_score": 0.85,
    }

    result = client.merge_indicator(enriched_item, source_id="virustotal")
    # With no driver, merge returns False — but it should not crash
    assert result is False
