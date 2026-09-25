# Threat Model

## 1. Master Password

| Threat | What could go wrong | Mitigation |
|---|---|---|
| Weak/guessable master password | Attacker brute-forces or guesses it, unlocking the entire vault | Enforce a minimum length/complexity on setup; use Argon2id (slow KDF) so guessing is computationally expensive |
| Master password stored insecurely | If stored in plaintext or with a fast hash (e.g. SHA-256), a stolen vault file is trivially crackable offline | Never store the raw password — only store the Argon2id-derived hash used for verification |
| Keylogging / shoulder surfing | Attacker captures the password as it's typed | Out of scope for a CLI tool at this stage — note it as an accepted risk in the report |

## 2. Vault at Rest (vault.json on disk)

| Threat | What could go wrong | Mitigation |
|---|---|---|
| Unauthorized file access | Attacker with disk access (stolen laptop, malware) reads vault.json directly | Vault contents are AES-256-GCM encrypted — file is useless without the master password |
| Tampering with the vault file | Attacker modifies ciphertext to corrupt or manipulate stored passwords | AES-GCM is authenticated encryption — any tampering causes decryption to fail loudly instead of returning corrupted data |
| Nonce reuse | Reusing the same nonce with the same key breaks AES-GCM's security guarantees | Generate a fresh random nonce (`os.urandom(12)`) every time the vault is re-saved |

## 3. Vault in Memory (while unlocked)

| Threat | What could go wrong | Mitigation |
|---|---|---|
| Decrypted data lingers in memory | A memory dump or crash log exposes plaintext passwords | Keep decrypted data in scope only as long as needed; avoid unnecessary copies of plaintext strings |
| Vault left unlocked | User walks away with an active unlocked session | Auto-lock after a period of inactivity (documented as a planned feature if not yet implemented) |

## 4. Interface (CLI)

| Threat | What could go wrong | Mitigation |
|---|---|---|
| Malformed / malicious input | Attacker feeds unexpected input (oversized strings, special characters) to crash the tool or corrupt data | Validate and sanitize all CLI input before it reaches the encryption or storage layers |
| Error messages leak information | Verbose error output reveals internal details (file paths, stack traces) useful to an attacker | Fail securely — show generic error messages to the user, log details separately if needed |
