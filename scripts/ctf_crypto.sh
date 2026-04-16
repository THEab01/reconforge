#!/usr/bin/env bash
# ctf_crypto.sh — Pipe a file or string into the crypto analyzer
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$1" ]; then
    echo "Usage: $0 <ciphertext_file_or_string>"
    exit 1
fi

if [ -f "$1" ]; then
    python3 "$SCRIPT_DIR/crypto/analyzer.py" "$1"
else
    echo "$1" | python3 "$SCRIPT_DIR/crypto/analyzer.py"
fi
