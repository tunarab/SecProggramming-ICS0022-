"""
main.py

CLI entry point for SecPass Manager.

Commands:
    init                      Create a new vault (prompts for a master password)
    add <name>                Add a new entry (prompts for username/password)
    get <name> [--show]       Retrieve an entry. Password is masked unless --show is passed.
    list                      List stored entry names (never shows passwords)
    delete <name>             Remove an entry

Every command that touches the vault prompts for the master password and
calls Vault.unlock() — the vault only ever opens on a successful
Argon2id + AES-GCM verification (see vault.py).
"""

import sys
import argparse
import getpass
from pathlib import Path

from vault import Vault, VaultAuthError

DEFAULT_VAULT_PATH = str(Path.home() / ".secpass_vault.json")


def mask(password: str) -> str:
    """Never print a real password unless the user explicitly asks for it."""
    return "*" * len(password) if password else ""


def prompt_master_password(confirm: bool = False) -> str:
    """
    getpass.getpass() does not echo input to the terminal — this is the
    first line of defense against shoulder-surfing / terminal screenshots.
    """
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords did not match.")
            sys.exit(1)
    return pw


def cmd_init(args):
    vault = Vault(args.vault)
    if vault.exists():
        print(f"A vault already exists at {args.vault}. Delete it first if you want to start over.")
        sys.exit(1)

    print("Creating a new vault.")
    master_password = prompt_master_password(confirm=True)
    if len(master_password) < 8:
        print("Master password should be at least 8 characters.")
        sys.exit(1)

    vault.create(master_password)
    print(f"Vault created at {args.vault}")


def cmd_add(args):
    vault = Vault(args.vault)
    _unlock_or_exit(vault, args.vault)

    username = input("Username: ")
    entry_password = getpass.getpass("Password to store (hidden input): ")

    vault.add_entry(args.name, username, entry_password)
    print(f"Entry '{args.name}' added.")


def cmd_get(args):
    vault = Vault(args.vault)
    _unlock_or_exit(vault, args.vault)

    try:
        entry = vault.get_entry(args.name)
    except KeyError as e:
        print(str(e))
        sys.exit(1)

    print(f"Entry: {args.name}")
    print(f"  Username: {entry['username']}")
    if args.show:
        print(f"  Password: {entry['password']}")
    else:
        print(f"  Password: {mask(entry['password'])}  (use --show to reveal)")


def cmd_list(args):
    vault = Vault(args.vault)
    _unlock_or_exit(vault, args.vault)

    names = vault.list_entries()
    if not names:
        print("Vault is empty.")
        return

    print("Stored entries:")
    for name in names:
        print(f"  - {name}")


def cmd_delete(args):
    vault = Vault(args.vault)
    _unlock_or_exit(vault, args.vault)

    try:
        vault.delete_entry(args.name)
    except KeyError as e:
        print(str(e))
        sys.exit(1)

    print(f"Entry '{args.name}' deleted.")


def _unlock_or_exit(vault: Vault, vault_path: str):
    if not vault.exists():
        print(f"No vault found at {vault_path}. Run 'init' first.")
        sys.exit(1)

    master_password = prompt_master_password()
    try:
        vault.unlock(master_password)
    except VaultAuthError as e:
        print(str(e))
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpass", description="SecPass Manager — a local encrypted password vault.")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH, help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH})")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create a new vault")

    p_add = subparsers.add_parser("add", help="Add a new entry")
    p_add.add_argument("name", help="Name for this entry (e.g. 'gmail')")

    p_get = subparsers.add_parser("get", help="Retrieve an entry")
    p_get.add_argument("name", help="Entry name to retrieve")
    p_get.add_argument("--show", action="store_true", help="Reveal the password in plaintext")

    subparsers.add_parser("list", help="List all entry names")

    p_delete = subparsers.add_parser("delete", help="Delete an entry")
    p_delete.add_argument("name", help="Entry name to delete")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "delete": cmd_delete,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
