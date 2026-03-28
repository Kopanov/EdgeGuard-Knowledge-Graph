#!/bin/bash
# EdgeGuard Pipeline Runner with Environment Variables (development helper)
#
# WARNING:
# - This script is a template for local use only.
# - Do NOT put real API keys in this file in version control.
# - Prefer exporting MISP_API_KEY in your shell or .env instead.

if [ -z "$MISP_API_KEY" ]; then
  echo "MISP_API_KEY is not set. Please export it in your environment before running."
  exit 1
fi

cd "$(dirname "$0")"
python3 run_pipeline.py
