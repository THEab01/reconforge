# ReconForge

A high-performance CTF toolkit for automated crypto analysis, binary reconnaissance, and web fingerprinting.

## Modules
- **crypto/** — Cipher identification & automated decryption
- **binary/** — Binary recon & fast pattern scanning (C)
- **web/** — HTTP fingerprinting & tech stack detection
- **scripts/** — Bash wrappers to chain tools together

## Setup
```bash
make setup
```

## Usage
```bash
# Crypto analysis
./scripts/ctf_crypto.sh <ciphertext_file>

# Binary recon
./scripts/ctf_binary.sh <binary_file>

# Web fingerprint
python3 web/fingerprint.py <url>
```

