#!/usr/bin/env python3
"""Decryption routines for common CTF ciphers."""

import base64
import binascii

def decode_base64(ct: str) -> str:
    try:
        return base64.b64decode(ct.strip()).decode(errors='replace')
    except Exception as e:
        return f"[!] Base64 failed: {e}"

def decode_hex(ct: str) -> str:
    try:
        return bytes.fromhex(ct.strip()).decode(errors='replace')
    except Exception as e:
        return f"[!] Hex failed: {e}"

def decode_caesar(ct: str) -> list[tuple[int, str]]:
    results = []
    ct_upper = ct.upper()
    for shift in range(1, 26):
        plain = ''.join(
            chr((ord(c) - 65 - shift) % 26 + 65) if c.isalpha() else c
            for c in ct_upper
        )
        results.append((shift, plain))
    return results

def decode_vigenere(ct: str, key: str) -> str:
    key = key.upper()
    result, ki = [], 0
    for c in ct.upper():
        if c.isalpha():
            result.append(chr((ord(c) - ord(key[ki % len(key)])) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
