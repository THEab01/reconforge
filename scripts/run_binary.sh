#!/usr/bin/env bash
# run_binary.sh — Run full binary recon + optional fast_scan pattern search
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <binary> [pattern]"
    exit 1
fi

BINARY="$1"
PATTERN="$2"

python3 "$SCRIPT_DIR/binary/recon.py" "$BINARY"

if [ -n "$PATTERN" ]; then
    echo "[*] Running fast_scan for pattern: $PATTERN"
    "$SCRIPT_DIR/binary/fast_scan" "$BINARY" "$PATTERN"
fi
