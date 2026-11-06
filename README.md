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

## Commands

- `init` — create a new vault with a master password
- `add <name>` — add a new password entry (prompts for username/password)
- `get <name>` — retrieve a stored entry (password masked by default; add `--show` to reveal)
- `list` — list all stored entry names
- `delete <name>` — remove an entry

All commands except `init` prompt for the master password and unlock the
vault before running. A wrong master password is rejected and the vault
stays locked.

## Tech stack

- Python 3
- `cryptography` (AES-256-GCM)
- `argon2-cffi` (Argon2id key derivation)

## Build & run

Tested on a clean machine with Python 3.10+ (macOS/Linux).

```bash
git clone https://github.com/tunarab/SecProggramming-ICS0022-.git
cd SecProggramming-ICS0022-
pip3 install -r requirements.txt

cd src
python3 main.py init
python3 main.py add gmail
python3 main.py list
python3 main.py get gmail
python3 main.py get gmail --show
python3 main.py delete gmail
```

By default the vault is stored at `~/.secpass_vault.json`. Use
`--vault <path>` on any command to point at a different file (useful for
testing without touching your real vault).

## Status

Checkpoint 1 (threat model & architecture) — complete.
Checkpoint 2 (core requirements implemented) — complete. See
[`PROGRESS.md`](PROGRESS.md) for details and what's still pending for
Checkpoint 3.
