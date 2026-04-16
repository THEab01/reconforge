#!/usr/bin/env python3
"""Binary Recon: runs standard checks on a binary and prints a summary report."""

import sys
import os
import subprocess
import re

def run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "[unavailable]"

def recon(path: str):
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"  ReconForge Binary Report: {os.path.basename(path)}")
    print(f"{'='*50}\n")

    print("[FILE TYPE]")
    print(run(["file", path]))

    print("\n[ARCHITECTURE / ELF HEADERS]")
    print(run(["readelf", "-h", path]))

    print("\n[LINKED LIBRARIES]")
    print(run(["ldd", path]))

    print("\n[SECURITY FLAGS]")
    print(run(["checksec", "--file", path]))

    print("\n[STRINGS (min length 6)]")
    strings = run(["strings", "-n", "6", path])
    # Highlight interesting strings
    for line in strings.splitlines():
        if re.search(r'flag|CTF|pass|key|secret|http|exec|system|/bin', line, re.I):
            print(f"  >> {line}")
        else:
            print(f"     {line}")

    print("\n[HIDDEN METADATA / COMMENTS]")
    print(run(["objdump", "-s", "--section=.comment", path]))

    print(f"\n{'='*50}\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 recon.py <binary>")
        sys.exit(1)
    recon(sys.argv[1])
