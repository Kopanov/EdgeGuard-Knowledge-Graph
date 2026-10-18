#!/usr/bin/env bash
#
# Writes the deployed commit into .env as EDGEGUARD_GIT_SHA. docker-compose.yml forwards it to
# airflow, api and graphql; the REST and GraphQL /health responses report it as git_sha and STIX
# exports as the X-EdgeGuard-Git-Sha header.
#
# The value lives in .env, not in a shell export, so every later docker compose command, from any
# shell, sees the same value and recreates no container because of it. Run it at every deploy,
# after the pull and before docker compose build: a commit left in .env by an earlier deploy is
# reported as the deployed one. ./install.sh runs it on a git checkout.
#
# Usage:
#   scripts/record_deployed_commit.sh            # the checked-out commit (git rev-parse --short HEAD)
#   scripts/record_deployed_commit.sh 6b6ea3f    # a named commit, e.g. the commit of a release tarball
#
# Replaces the EDGEGUARD_GIT_SHA= line of .env in place (appends one when there is none, and drops
# any further ones) and keeps the rest of the file, its owner and its mode. Runs on bash 3.2 (the
# macOS system bash) and later.
#
# Exit codes:
#   0 — written
#   1 — no .env, no commit to record, or a value that is not a commit id (7 to 40 hex digits)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"

if [[ $# -gt 1 ]]; then
    echo "FAIL: at most one argument (the commit)" >&2
    exit 1
fi
if [[ $# -eq 1 ]]; then
    COMMIT="$1"
elif ! COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null); then
    echo "FAIL: $ROOT is not a git checkout; name the commit: $0 <commit>" >&2
    exit 1
fi

COMMIT_RE='^[0-9a-f]{7,40}$'
if ! [[ "$COMMIT" =~ $COMMIT_RE ]]; then
    echo "FAIL: '$COMMIT' is not a commit id (7 to 40 lowercase hex digits)" >&2
    exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
    echo "FAIL: $ENV_FILE not found (cp .env.example .env first)" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
awk -v sha="$COMMIT" '
    /^EDGEGUARD_GIT_SHA=/ { if (!done) { print "EDGEGUARD_GIT_SHA=" sha; done = 1 } next }
    { print }
    END { if (!done) print "EDGEGUARD_GIT_SHA=" sha }
' "$ENV_FILE" > "$tmp"
# Writing through the existing file keeps its owner and mode (.env holds secrets).
cat "$tmp" > "$ENV_FILE"
echo "EDGEGUARD_GIT_SHA=$COMMIT written to $ENV_FILE"
