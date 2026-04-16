#!/usr/bin/env python3
"""Crypto Analyzer: identify cipher type and attempt decryption."""

import math
import re
import base64
import binascii
import sys
from collections import Counter
from decoders import decode_base64, decode_hex, decode_caesar, decode_vigenere

def entropy(data: str) -> float:
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def identify(ciphertext: str) -> list[str]:
    candidates = []
    ct = ciphertext.strip()

    # Base64
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', ct) and len(ct) % 4 == 0:
        candidates.append('base64')

    # Hex
    if re.fullmatch(r'[0-9a-fA-F]+', ct) and len(ct) % 2 == 0:
        candidates.append('hex')

    # Caesar / Vigenere (only letters)
    if re.fullmatch(r'[A-Za-z\s]+', ct):
        e = entropy(ct.replace(' ', '').upper())
        candidates.append('caesar' if e < 3.8 else 'vigenere')

    return candidates or ['unknown']

def analyze(ciphertext: str):
    candidates = identify(ciphertext)
    print(f"[*] Entropy     : {entropy(ciphertext.strip()):.4f}")
    print(f"[*] Candidates  : {', '.join(candidates)}\n")

    for cipher in candidates:
        print(f"--- Attempting {cipher} ---")
        if cipher == 'base64':
            print(decode_base64(ciphertext))
        elif cipher == 'hex':
            print(decode_hex(ciphertext))
        elif cipher == 'caesar':
            for shift, plain in decode_caesar(ciphertext):
                print(f"  shift={shift:2d}: {plain}")
        elif cipher == 'vigenere':
            print("  [!] Vigenere requires a key. Use: decoders.decode_vigenere(ct, key)")

if __name__ == '__main__':
    ct = sys.stdin.read() if len(sys.argv) < 2 else open(sys.argv[1]).read()
    analyze(ct.strip())
