"""
crypto_utils.py

Key derivation and authenticated encryption used by the vault.

Scheme (decided at Checkpoint 1):
  - Argon2id derives a 256-bit key from the master password + a random salt.
  - AES-256-GCM encrypts the vault contents. GCM is authenticated encryption:
    if the wrong key is used, or the ciphertext has been tampered with,
    decryption raises an exception instead of returning garbage/plaintext.
    This is what makes "master password authentication" work for free —
    there's no separate password hash to check; a wrong master password
    simply fails to decrypt.
"""

import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id parameters. These are deliberately expensive (slow) so that
# brute-forcing the master password offline is costly. Tuned for a
# student laptop to unlock in well under a second.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
KEY_LENGTH = 32  # 256-bit key for AES-256

SALT_LENGTH = 16
NONCE_LENGTH = 12  # Standard nonce size for AES-GCM


def generate_salt() -> bytes:
    """A fresh random salt, generated once per vault (at creation)."""
    return os.urandom(SALT_LENGTH)


def generate_nonce() -> bytes:
    """
    A fresh random nonce for EACH encryption operation.

    Common mistake: reusing a nonce with the same key breaks AES-GCM's
    security guarantees entirely. We generate a new one every time the
    vault is saved, so this must never be cached or reused.
    """
    return os.urandom(NONCE_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password via Argon2id."""
    if not master_password:
        raise ValueError("Master password must not be empty.")

    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,  # Argon2id variant
    )


def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext with AES-256-GCM.

    Raises cryptography.exceptions.InvalidTag if the key is wrong
    (i.e. the master password was wrong) or the ciphertext was tampered
    with. The caller is expected to catch this and treat it as a failed
    authentication attempt — see vault.py's unlock().
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
