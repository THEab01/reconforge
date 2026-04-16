#!/usr/bin/env python3
"""JWT decoder and cookie parser utilities."""

import base64
import json

def decode_jwt(token: str) -> dict:
    try:
        header, payload, _ = token.split('.')
        def pad(s): return s + '=' * (-len(s) % 4)
        return {
            "header":  json.loads(base64.urlsafe_b64decode(pad(header))),
            "payload": json.loads(base64.urlsafe_b64decode(pad(payload))),
        }
    except Exception as e:
        return {"error": str(e)}

def parse_cookies(cookie_header: str) -> dict:
    return dict(
        part.strip().split('=', 1)
        for part in cookie_header.split(';')
        if '=' in part
    )

if __name__ == '__main__':
    import sys
    token = sys.argv[1] if len(sys.argv) > 1 else input("JWT: ").strip()
    print(json.dumps(decode_jwt(token), indent=2))
