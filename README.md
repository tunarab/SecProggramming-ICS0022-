
# SecPass Manager

A command-line password manager built for ICS0022 Secure Programming (TalTech).
Passwords are encrypted at rest using AES-256-GCM, with the encryption key
derived from a user's master password via Argon2id.

## Scope

This project implements a local, single-user password vault. It covers:
- Master password setup and verification
- Encrypting and decrypting a vault of stored credentials
- Basic CRUD operations on vault entries via a CLI

It does not (at this stage) cover multi-user support, cloud sync, or
browser integration.

## Architecture

See [`design/architecture.md`](design/architecture.md) for the component
diagram and data flow, and [`design/threat-model.md`](design/threat-model.md)
for the threat model.

## Planned commands

- `add <name>` — add a new password entry
- `get <name>` — retrieve a stored password
- `list` — list all stored entry names
- `delete <name>` — remove an entry
- `init` — create a new vault with a master password

## Tech stack

- Python 3
- `cryptography` (AES-256-GCM)
- `argon2-cffi` (Argon2id key derivation)

## Build & run

\`\`\`bash
pip3 install -r requirements.txt
python3 src/main.py
\`\`\`

## Status

Work in progress — Checkpoint 1 (threat model & architecture) complete.
