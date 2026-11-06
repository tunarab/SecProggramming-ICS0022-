"""
vault.py

Vault storage and master-password authentication.

Vault file format (JSON), matching the Checkpoint 1 design doc:
{
    "kdf": "argon2id",
    "salt": "<base64>",
    "nonce": "<base64>",
    "ciphertext": "<base64>"
}

The "ciphertext" field, once decrypted, is itself JSON:
{
    "entry_name": {"username": "...", "password": "..."},
    ...
}

The vault NEVER stores the master password itself — only the salt
needed to re-derive the key from whatever password the user types in.
"""

import json
import base64
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag

from crypto_utils import derive_key, encrypt, decrypt, generate_salt


class VaultAuthError(Exception):
    """Raised when the master password is wrong, or the vault file is corrupt/tampered."""
    pass


class Vault:
    def __init__(self, path: str):
        self.path = Path(path)
        self._key = None          # Only held in memory while unlocked
        self._entries = None      # Decrypted entries, only while unlocked
        self._salt = None

    # ------------------------------------------------------------------
    # Setup / authentication
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        """Create a brand-new, empty vault protected by master_password."""
        if self.exists():
            raise FileExistsError(f"Vault already exists at {self.path}")

        salt = generate_salt()
        key = derive_key(master_password, salt)

        self._salt = salt
        self._key = key
        self._entries = {}
        self._write_to_disk()

    def unlock(self, master_password: str) -> None:
        """
        Attempt to unlock the vault.

        The vault unlocks ONLY on successful verification: we derive a key
        from the supplied password and try to decrypt the stored
        ciphertext. AES-GCM's authentication tag means a wrong password
        (wrong key) makes decryption fail — there's no separate "is this
        password correct?" check to get out of sync with the real key.
        """
        if not self.exists():
            raise FileNotFoundError(f"No vault found at {self.path}")

        with open(self.path, "r") as f:
            data = json.load(f)

        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])

        key = derive_key(master_password, salt)

        try:
            plaintext = decrypt(key, nonce, ciphertext)
        except InvalidTag:
            # Deliberately vague — don't tell an attacker WHY it failed
            # (wrong password vs. tampered file). See threat model.
            raise VaultAuthError("Incorrect master password or corrupted vault.")

        self._salt = salt
        self._key = key
        self._entries = json.loads(plaintext.decode("utf-8"))

    def _require_unlocked(self) -> None:
        if self._key is None or self._entries is None:
            raise VaultAuthError("Vault is locked. Call unlock() first.")

    # ------------------------------------------------------------------
    # Entry operations (all require the vault to be unlocked)
    # ------------------------------------------------------------------

    def add_entry(self, name: str, username: str, password: str) -> None:
        self._require_unlocked()
        if not name:
            raise ValueError("Entry name must not be empty.")
        self._entries[name] = {"username": username, "password": password}
        self._write_to_disk()

    def get_entry(self, name: str) -> dict:
        self._require_unlocked()
        if name not in self._entries:
            raise KeyError(f"No entry named '{name}'.")
        return self._entries[name]

    def list_entries(self) -> list:
        self._require_unlocked()
        # Only names — never the stored passwords.
        return sorted(self._entries.keys())

    def delete_entry(self, name: str) -> None:
        self._require_unlocked()
        if name not in self._entries:
            raise KeyError(f"No entry named '{name}'.")
        del self._entries[name]
        self._write_to_disk()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _write_to_disk(self) -> None:
        """
        Re-encrypt the whole entry set and write it to the vault file.

        A fresh nonce is generated on every write (see crypto_utils) —
        never reuse one across saves.
        """
        plaintext = json.dumps(self._entries).encode("utf-8")
        nonce, ciphertext = encrypt(self._key, plaintext)

        data = {
            "kdf": "argon2id",
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

        # Write to a temp file then rename, so a crash mid-write can't
        # leave a half-written, corrupted vault file on disk.
        tmp_path = str(self.path) + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.path)
