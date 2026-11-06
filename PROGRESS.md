# Checkpoint 2 — Progress Note

## What's working

- **Vault storage**: `src/vault.py` creates and persists a vault as a JSON
  file (`kdf`, `salt`, `nonce`, `ciphertext` fields), matching the format
  decided at Checkpoint 1.
- **Encryption at rest**: entries are serialized to JSON, then encrypted
  with AES-256-GCM. The key is derived from the master password via
  Argon2id (`src/crypto_utils.py`). Confirmed by inspecting the vault
  file on disk — no entry name, username, or password appears in
  plaintext anywhere in the file.
- **Master password authentication**: the vault only unlocks on a
  successful decrypt. Because AES-GCM is authenticated encryption, a
  wrong master password produces the wrong key, which causes decryption
  to fail with an `InvalidTag` error — there's no separate password
  check to get out of sync with the real key. Tested with both a correct
  and an incorrect password; the incorrect one is rejected and the CLI
  exits non-zero.
- **CLI**: `init`, `add`, `get`, `list`, `delete` all implemented in
  `src/main.py`, using `argparse` for commands and `getpass` for hidden
  password input.
- **No cleartext passwords printed by default**: `get <name>` masks the
  password (`***...`) unless `--show` is explicitly passed. `list` only
  ever shows entry names, never passwords.

## What's not done yet (planned for Checkpoint 3)

- Input validation is minimal — entry names aren't yet sanitized against
  unusual characters, and there's no length/complexity enforcement
  beyond an 8-character minimum on the master password.
- No auto-lock after inactivity (noted as an accepted risk in the
  Checkpoint 1 threat model; still pending).
- No automated test suite yet — testing so far has been manual, as shown
  below.

## How it was tested

Ran the full command set end-to-end against a scratch vault:
`init` → `add` → `list` → `get` (masked) → `get --show` → `get` with a
wrong master password (confirmed rejected, non-zero exit) → `delete` →
`list` (confirmed empty). Also inspected the raw vault JSON file to
confirm no plaintext secrets are stored on disk.
