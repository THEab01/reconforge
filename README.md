# ReconForge

A modular CTF toolkit for automated crypto analysis, binary reconnaissance, and web fingerprinting — built for speed during competitions.

## Modules

| Module | Description |
|---|---|
| `crypto/` | Cipher identification (Base64, Hex, Caesar, Vigenère) & automated decryption |
| `binary/` | Binary recon report + high-speed C pattern scanner |
| `web/` | HTTP fingerprinting, tech stack detection, WAF detection, JWT decoding |
| `scripts/` | Bash executors to run each module from the command line |

## Setup

```bash
make setup
```

## Usage

### Crypto
```bash
./scripts/ctf_crypto.sh <ciphertext_file_or_string>
```

### Binary
```bash
./scripts/run_binary.sh <binary> [pattern]
```

### Web
```bash
./scripts/run_web.sh <url>
```

## Project Structure

```
reconforge/
├── crypto/
│   ├── analyzer.py       # Entropy analysis & cipher identification
│   └── decoders.py       # Decryption routines
├── binary/
│   ├── recon.py          # Binary recon report
│   └── fast_scan.c       # High-speed pattern scanner (C)
├── web/
│   ├── fingerprint.py    # HTTP fingerprinter & tech stack detector
│   └── decoders.py       # JWT decoder & cookie parser
├── scripts/
│   ├── ctf_crypto.sh     # Crypto analyzer executor
│   ├── ctf_binary.sh     # Binary recon executor (with pattern search)
│   ├── run_binary.sh     # Binary recon executor
│   └── run_web.sh        # Web fingerprinter executor
├── config/
│   └── signatures.json   # WAF & framework fingerprint signatures
├── requirements.txt
└── Makefile
```

## Dependencies

- Python 3.10+
- `requests`, `python-magic`, `pwntools`, `PyJWT`
- `gcc` (for compiling `fast_scan.c`)
- Standard Linux tools: `file`, `strings`, `readelf`, `objdump`, `checksec`
