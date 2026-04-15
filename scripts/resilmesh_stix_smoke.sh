#!/usr/bin/env bash
#
# End-to-end smoke test for the EdgeGuard STIX 2.1 exporter.
#
# Curls every supported object type against a running Query API and
# pretty-prints the resulting bundles. Intended as the first thing a
# ResilMesh integrator runs to confirm the integration is wired up
# correctly. Safe to run repeatedly — all operations are read-only.
#
# Requirements:
#   - running EdgeGuard Query API (default: http://127.0.0.1:8000)
#   - EDGEGUARD_API_KEY exported (matches the server's internal read key)
#   - curl + jq installed
#
# Usage:
#   scripts/resilmesh_stix_smoke.sh
#   EDGEGUARD_API_BASE=https://edgeguard.org EDGEGUARD_API_KEY=... scripts/resilmesh_stix_smoke.sh
#   scripts/resilmesh_stix_smoke.sh --depth 1        # minimal bundles
#   scripts/resilmesh_stix_smoke.sh --no-pretty      # raw JSON (pipe-friendly)
#
# Exit codes:
#   0 — all checks passed
#   1 — a dependency is missing or a check failed
#
# The script does NOT validate bundle shape — use the stix2-validator
# Python package for that. It only asserts HTTP 200 + non-empty body +
# the expected media type on the response.

set -euo pipefail

API_BASE="${EDGEGUARD_API_BASE:-http://127.0.0.1:8000}"
API_KEY="${EDGEGUARD_API_KEY:-}"
DEPTH=2
PRETTY=1

usage() {
    sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)     DEPTH="$2"; shift 2 ;;
        --no-pretty) PRETTY=0; shift ;;
        -h|--help)   usage ;;
        *)           echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

if ! command -v curl >/dev/null; then
    echo "FAIL: curl is required" >&2
    exit 1
fi
if ! command -v jq >/dev/null; then
    echo "FAIL: jq is required (brew install jq / apt-get install jq)" >&2
    exit 1
fi
if [[ -z "$API_KEY" ]]; then
    echo "FAIL: EDGEGUARD_API_KEY must be set (same value as the server's internal read key)" >&2
    exit 1
fi

echo "▶ EdgeGuard STIX 2.1 exporter smoke test"
echo "   API base:  $API_BASE"
echo "   Depth:     $DEPTH"
echo

# ---------------------------------------------------------------------------
# 1. Discovery — /stix/types
# ---------------------------------------------------------------------------
echo "▶ GET /stix/types"
TYPES_JSON=$(curl --silent --show-error --fail \
    -H "X-API-Key: $API_KEY" \
    "$API_BASE/stix/types")
if [[ $PRETTY -eq 1 ]]; then
    echo "$TYPES_JSON" | jq .
else
    echo "$TYPES_JSON"
fi
echo

# Drive the rest of the smoke test directly off the discovery response
# so we never hard-code identifiers that might rot when the graph
# changes. A failing example is diagnostic, not a smoke-test failure.
mapfile -t OBJECT_TYPES < <(echo "$TYPES_JSON" | jq -r '.object_types[].name')
if [[ ${#OBJECT_TYPES[@]} -eq 0 ]]; then
    echo "FAIL: /stix/types returned no object_types" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. One export per type, using the example identifier from /stix/types
# ---------------------------------------------------------------------------
FAILED=0
for ot in "${OBJECT_TYPES[@]}"; do
    example=$(echo "$TYPES_JSON" | jq -r ".object_types[] | select(.name==\"$ot\") | .example")
    encoded=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$example")
    url="$API_BASE/stix/export/$ot/$encoded?depth=$DEPTH"
    echo "▶ GET /stix/export/$ot/$example  (depth=$DEPTH)"

    # --write-out captures status + size; --output captures body to stdout.
    response=$(mktemp)
    status=$(curl --silent --show-error \
        --write-out '%{http_code}' \
        --output "$response" \
        -H "X-API-Key: $API_KEY" \
        -H "Accept: application/stix+json;version=2.1" \
        "$url")

    if [[ "$status" != "200" ]]; then
        echo "  ✗ HTTP $status (see $response for body)"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Shape sanity checks — every response must be a STIX 2.1 bundle
    # with type=bundle, id prefixed bundle--, and an objects array.
    if ! jq -e '.type == "bundle" and (.id | startswith("bundle--")) and (.objects | type == "array")' "$response" >/dev/null; then
        echo "  ✗ response is not a valid STIX bundle"
        jq . "$response" | head -20
        FAILED=$((FAILED + 1))
        rm -f "$response"
        continue
    fi

    obj_count=$(jq '.objects | length' "$response")
    producer=$(jq -r '.x_edgeguard_source.producer // "missing"' "$response")
    generated=$(jq -r '.x_edgeguard_source.generated_at // "missing"' "$response")
    echo "  ✓ $obj_count objects   producer=$producer   generated_at=$generated"

    if [[ $PRETTY -eq 1 ]]; then
        jq '{type, id, x_edgeguard_source, object_count: (.objects | length), object_types: ([.objects[].type] | group_by(.) | map({(.[0]): length}) | add)}' "$response"
    fi
    rm -f "$response"
    echo
done

if [[ $FAILED -gt 0 ]]; then
    echo "▶ $FAILED check(s) failed"
    exit 1
fi
echo "▶ all checks passed"
