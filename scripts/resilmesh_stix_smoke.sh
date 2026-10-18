#!/usr/bin/env bash
#
# End-to-end smoke test for the EdgeGuard STIX 2.1 exporter.
#
# Reads /stix/types, then exports one object of every listed type from a
# running Query API and checks each bundle. Intended as the first thing a
# ResilMesh integrator runs to confirm the integration is wired up
# correctly. Safe to run repeatedly — all operations are read-only.
# Runs on bash 3.2 (the macOS system bash) and later.
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
#   scripts/resilmesh_stix_smoke.sh --actor "Lazarus Group" --cve CVE-2017-0144
#
# Identifiers (each exists in a baseline graph; override with a flag):
#   --actor NAME        default APT28
#   --technique ID      default T1059
#   --cve ID            default CVE-2021-44228
#   --indicator VALUE   default: the newest indicator GET /indicators?limit=1 returns
# A type /stix/types lists without an identifier here is exported at its
# /stix/types example.
#
# Checks for every type: HTTP 200; a STIX bundle (type bundle, id
# bundle--..., an objects array); and at least one object besides the
# producer identity, the extension definition and the TLP marking
# definitions. A bundle without one means the identifier is not in the
# graph, and the check fails.
#
# Exit codes:
#   0 — all checks passed
#   1 — a dependency is missing, GET /stix/types failed, or a check failed
#
# The script does NOT validate the bundle against the STIX 2.1
# specification — use the stix2-validator Python package for that.

set -euo pipefail

API_BASE="${EDGEGUARD_API_BASE:-http://127.0.0.1:8000}"
API_KEY="${EDGEGUARD_API_KEY:-}"
DEPTH=2
PRETTY=1
ACTOR="APT28"
TECHNIQUE="T1059"
CVE="CVE-2021-44228"
INDICATOR=""

usage() {
    # The header comment above, without the leading "# ".
    awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
    exit 0
}

need_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "FAIL: $1 needs a value" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)     need_value "$@"; DEPTH="$2"; shift 2 ;;
        --actor)     need_value "$@"; ACTOR="$2"; shift 2 ;;
        --technique) need_value "$@"; TECHNIQUE="$2"; shift 2 ;;
        --cve)       need_value "$@"; CVE="$2"; shift 2 ;;
        --indicator) need_value "$@"; INDICATOR="$2"; shift 2 ;;
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
# Guarded, so an unreachable API or an HTTP error ends the run with exit code 1, not curl's.
if ! TYPES_JSON=$(curl --silent --show-error --fail \
    -H "X-API-Key: $API_KEY" \
    "$API_BASE/stix/types"); then
    echo "FAIL: GET /stix/types failed (curl error above)" >&2
    exit 1
fi
# Every later read of the discovery response relies on this shape.
if ! echo "$TYPES_JSON" | jq -e '.object_types | type == "array" and length > 0 and all(.[]; type == "object" and (.name | type == "string"))' >/dev/null 2>&1; then
    echo "FAIL: /stix/types returned no object_types (response is not the discovery JSON)" >&2
    exit 1
fi
if [[ $PRETTY -eq 1 ]]; then
    echo "$TYPES_JSON" | jq .
else
    echo "$TYPES_JSON"
fi
echo

# The object types come from the discovery response, so a type the server
# adds is exported too. A while-read loop instead of mapfile, which bash
# 3.2 does not have.
OBJECT_TYPES=()
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        OBJECT_TYPES+=("$line")
    fi
done < <(echo "$TYPES_JSON" | jq -r '.object_types[].name')
if [[ ${#OBJECT_TYPES[@]} -eq 0 ]]; then
    echo "FAIL: /stix/types returned no object_types" >&2
    exit 1
fi

# The newest indicator of the graph, unless --indicator names one.
lookup_indicator() {
    local body
    if ! body=$(curl --silent --show-error --fail \
        -H "X-API-Key: $API_KEY" \
        "$API_BASE/indicators?limit=1"); then
        return 1
    fi
    echo "$body" | jq -r '.indicators[0].value // empty'
}

# ---------------------------------------------------------------------------
# 2. One export per type
# ---------------------------------------------------------------------------
FAILED=0
for ot in "${OBJECT_TYPES[@]}"; do
    case "$ot" in
        actor)     identifier="$ACTOR" ;;
        technique) identifier="$TECHNIQUE" ;;
        cve)       identifier="$CVE" ;;
        indicator)
            identifier="$INDICATOR"
            reason="GET /indicators?limit=1 returned none"
            if [[ -z "$identifier" ]] && ! identifier=$(lookup_indicator); then
                # An unreachable API, an HTTP error or a body that is not JSON is a failed lookup,
                # not an empty graph.
                identifier=""
                reason="GET /indicators?limit=1 failed (unreachable, HTTP error or not JSON)"
            fi
            if [[ -z "$identifier" ]]; then
                echo "▶ GET /stix/export/indicator/..."
                echo "  ✗ no indicator to export: $reason (pass --indicator VALUE)"
                FAILED=$((FAILED + 1))
                echo
                continue
            fi
            ;;
        *)
            identifier=$(echo "$TYPES_JSON" | jq -r --arg ot "$ot" '.object_types[] | select(.name == $ot) | .example')
            ;;
    esac
    encoded=$(jq -rn --arg v "$identifier" '$v | @uri')
    url="$API_BASE/stix/export/$ot/$encoded?depth=$DEPTH"
    echo "▶ GET /stix/export/$ot/$identifier  (depth=$DEPTH)"

    # --write-out captures status + size; --output captures body to stdout;
    # --dump-header keeps the response headers (the build is a header).
    response=$(mktemp)
    headers=$(mktemp)
    status=$(curl --silent --show-error \
        --write-out '%{http_code}' \
        --output "$response" \
        --dump-header "$headers" \
        -H "X-API-Key: $API_KEY" \
        -H "Accept: application/stix+json;version=2.1" \
        "$url" || true)

    if [[ "$status" != "200" ]]; then
        echo "  ✗ HTTP $status (see $response for body)"
        FAILED=$((FAILED + 1))
        rm -f "$headers"
        echo
        continue
    fi

    # Shape sanity checks — every response must be a STIX 2.1 bundle
    # with type=bundle, id prefixed bundle--, and an objects array of
    # objects that each carry a string type (the reads below rely on it).
    if ! jq -e '.type == "bundle" and (.id | startswith("bundle--")) and (.objects | type == "array" and all(.[]; type == "object" and (.type | type == "string")))' "$response" >/dev/null 2>&1; then
        echo "  ✗ response is not a valid STIX bundle"
        # The start of the body; never fatal, so the remaining types are still checked.
        if jq empty "$response" >/dev/null 2>&1; then
            jq . "$response" | head -20 || true
        else
            head -c 2000 "$response" || true
            echo
        fi
        FAILED=$((FAILED + 1))
        rm -f "$response" "$headers"
        echo
        continue
    fi

    # Every bundle carries the producer identity (identity_class system, with
    # an x_edgeguard_exporter property), the extension definition and the TLP
    # marking definitions it references. A bundle holding nothing else has no
    # graph object: the identifier is not in the graph.
    content_count=$(jq '[.objects[] | select(
        ((.type == "identity" and (.identity_class == "system" or has("x_edgeguard_exporter")))
         or .type == "extension-definition"
         or .type == "marking-definition") | not)] | length' "$response")
    if [[ "$content_count" -eq 0 ]]; then
        echo "  ✗ the bundle holds only the producer identity, extension definition and markings: $ot $identifier is not in the graph"
        FAILED=$((FAILED + 1))
        rm -f "$response" "$headers"
        echo
        continue
    fi

    # The build that served the bundle is the X-EdgeGuard-Git-Sha response
    # header (absent when the server has no EDGEGUARD_GIT_SHA).
    obj_count=$(jq '.objects | length' "$response")
    producer=$(jq -r '[.objects[] | select(.type == "identity" and has("x_edgeguard_exporter"))][0].name // "missing"' "$response")
    build=$(grep -i '^x-edgeguard-git-sha:' "$headers" | head -1 | cut -d: -f2- | tr -d ' \r' || true)
    echo "  ✓ $obj_count objects ($content_count from the graph)   producer=$producer   build=${build:-not set}"

    if [[ $PRETTY -eq 1 ]]; then
        jq '{type, id, producer: ([.objects[] | select(.type == "identity" and has("x_edgeguard_exporter"))][0]), object_count: (.objects | length), object_types: ([.objects[].type] | group_by(.) | map({(.[0]): length}) | add)}' "$response"
    fi
    rm -f "$response" "$headers"
    echo
done

if [[ $FAILED -gt 0 ]]; then
    echo "▶ $FAILED check(s) failed"
    exit 1
fi
echo "▶ all checks passed"
