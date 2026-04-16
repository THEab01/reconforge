#!/usr/bin/env bash
# run_web.sh — Run web fingerprinting on a target URL
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

python3 "$SCRIPT_DIR/web/fingerprint.py" "$1"
