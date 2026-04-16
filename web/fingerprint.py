#!/usr/bin/env python3
"""Web Fingerprinter: identify tech stack, WAF, and attack surface from HTTP responses."""

import sys
import json
import re
import base64
from pathlib import Path
import requests

SIGS_PATH = Path(__file__).parent.parent / "config" / "signatures.json"
COMMON_PATHS = ["/robots.txt", "/.git/HEAD", "/api/", "/graphql", "/admin", "/.env"]

def load_sigs() -> dict:
    with open(SIGS_PATH) as f:
        return json.load(f)

def decode_jwt(token: str) -> dict:
    try:
        parts = token.split('.')
        payload = parts[1] + '=' * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}

def fingerprint(url: str):
    sigs = load_sigs()
    url = url.rstrip('/')
    session = requests.Session()
    session.headers['User-Agent'] = 'Mozilla/5.0'

    print(f"\n{'='*50}")
    print(f"  ReconForge Web Report: {url}")
    print(f"{'='*50}\n")

    # --- Base request ---
    try:
        r = session.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)

    headers = {k.lower(): v for k, v in r.headers.items()}

    # --- Headers ---
    print("[HEADERS]")
    for h in ['server', 'x-powered-by', 'x-generator', 'via', 'x-aspnet-version']:
        if h in headers:
            print(f"  {h}: {headers[h]}")

    # --- Framework detection ---
    print("\n[FRAMEWORK]")
    detected = []
    body = r.text.lower()
    for fw, patterns in sigs.get("frameworks", {}).items():
        for p in patterns:
            if p.lower() in body or p.lower() in str(headers):
                detected.append(fw)
                break
    print(f"  {', '.join(detected) if detected else 'unknown'}")

    # --- WAF detection ---
    print("\n[WAF]")
    waf_probe = session.get(url + "/?q=<script>alert(1)</script>", timeout=8)
    waf_headers = {k.lower(): v for k, v in waf_probe.headers.items()}
    waf_found = []
    for waf, patterns in sigs.get("wafs", {}).items():
        for p in patterns:
            if p.lower() in str(waf_headers) or p.lower() in waf_probe.text.lower():
                waf_found.append(waf)
                break
    print(f"  {', '.join(waf_found) if waf_found else 'none detected'}")

    # --- Cookies ---
    print("\n[COOKIES]")
    for name, val in session.cookies.items():
        print(f"  {name}: {val[:60]}{'...' if len(val) > 60 else ''}")
        if val.count('.') == 2 and val.startswith('ey'):
            decoded = decode_jwt(val)
            if decoded:
                print(f"    [JWT] {json.dumps(decoded, indent=6)}")

    # --- Common paths ---
    print("\n[ENDPOINT SCAN]")
    for path in COMMON_PATHS:
        try:
            resp = session.get(url + path, timeout=5, allow_redirects=False)
            status = resp.status_code
            flag = ">>" if status in (200, 301, 302) else "  "
            print(f"  {flag} {path} [{status}]")
        except Exception:
            print(f"     {path} [error]")

    print(f"\n{'='*50}\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 fingerprint.py <url>")
        sys.exit(1)
    fingerprint(sys.argv[1])
