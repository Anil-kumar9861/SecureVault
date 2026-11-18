import base64
import json

import os
import tempfile

from pathlib import Path
from securevault.vault.crypto import (
    KdfParams,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)
from securevault.vault.service import validate_master_password

BACKUP_VERSION = 1
BACKUP_AAD = b"securevault-backup-v1"
MAX_BACKUP_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_BACKUP_TIME_COST = 5
MAX_BACKUP_MEMORY_KIB = 262144  # 256 MB
MAX_BACKUP_PARALLELISM = 8


def create_backup(credentials: list[dict], backup_password: str) -> dict:
    """Encrypt credentials and return a JSON-compatible backup envelope."""

    if not isinstance(credentials, list):
        raise ValueError("Credentials must be a list")

    validate_master_password(backup_password)

    # Create fresh salt and derive an encryption key.
    params = KdfParams()
    salt = generate_salt()
    key = derive_key(backup_password, salt, params)

    # Convert all credentials into JSON bytes.
    payload = {
        "credentials": credentials,
    }

    plaintext = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")

    # Encrypt the complete backup.
    nonce, ciphertext = encrypt(key, plaintext, BACKUP_AAD)

    # Convert binary values into Base64 strings.
    return {
        "version": BACKUP_VERSION,
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": params.time_cost,
            "memory_kib": params.memory_kib,
            "parallelism": params.parallelism,
        },
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def validate_backup_credentials(credentials: list) -> None:
    """Validate the structure of imported backup credentials."""

    if not isinstance(credentials, list):
        raise ValueError("Invalid credentials data")

    for item in credentials:
        if not isinstance(item, dict):
            raise ValueError("Invalid credential in backup")

        if not isinstance(item.get("service"), str) or not item["service"].strip():
            raise ValueError("Invalid service in backup")

        if not isinstance(item.get("username"), str):
            raise ValueError("Invalid username in backup")

        if not isinstance(item.get("password"), str) or not item["password"]:
            raise ValueError("Invalid password in backup")

        for field in ("label", "url", "notes"):
            if field in item and not isinstance(item[field], str):
                raise ValueError(f"Invalid {field} in backup")


def load_backup(backup_data: dict, backup_password: str) -> list[dict]:
    """Decrypt a backup and return its credential dictionaries."""

    if not isinstance(backup_data, dict):
        raise ValueError("Invalid backup format")

    if backup_data.get("version") != BACKUP_VERSION:
        raise ValueError("Unsupported backup version")

    if backup_data.get("kdf") != "argon2id":
        raise ValueError("Unsupported key derivation algorithm")

    if not isinstance(backup_password, str) or not backup_password.strip():
        raise ValueError("Backup password cannot be empty")

    try:
        params_data = backup_data["kdf_params"]

        time_cost = params_data["time_cost"]
        memory_kib = params_data["memory_kib"]
        parallelism = params_data["parallelism"]

        if (
            time_cost > MAX_BACKUP_TIME_COST
            or memory_kib > MAX_BACKUP_MEMORY_KIB
            or parallelism > MAX_BACKUP_PARALLELISM
        ):
            raise ValueError("Backup KDF parameters exceed allowed limits")

        params = KdfParams(
            time_cost=time_cost,
            memory_kib=memory_kib,
            parallelism=parallelism,
        )

        salt = base64.b64decode(backup_data["salt"], validate=True)
        nonce = base64.b64decode(backup_data["nonce"], validate=True)
        ciphertext = base64.b64decode(backup_data["ciphertext"], validate=True)

        key = derive_key(backup_password, salt, params)

        plaintext = decrypt(key, nonce, ciphertext, BACKUP_AAD)

        payload = json.loads(plaintext.decode("utf-8"))

        credentials = payload["credentials"]

        credentials = payload["credentials"]

        validate_backup_credentials(credentials)

        return credentials

    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or corrupted backup file") from exc


def save_backup(
    file_path: str,
    backup_data: dict,
    overwrite: bool = False,
) -> None:
    """Save an encrypted backup as a JSON file."""

    destination = Path(file_path)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Backup already exists: {destination}")

    # Ensure the destination directory exists.
    if not destination.parent.exists():
        raise FileNotFoundError("Backup directory does not exist")

    # Convert the backup dictionary into JSON.
    json_data = json.dumps(
        backup_data,
        indent=4,
        ensure_ascii=False,
    )

    temp_path = None

    try:
        # Create a temporary file in the same directory.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(json_data)

        # Replace the destination with the completed file.
        os.replace(temp_path, destination)

    finally:
        # Clean up the temporary file if something goes wrong.
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def read_backup(file_path: str) -> dict:
    """Read an encrypted JSON backup file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Backup file not found: {file_path}")

    if path.stat().st_size > MAX_BACKUP_FILE_SIZE:
        raise ValueError("Backup file exceeds the maximum allowed size of 10 MB")

    try:
        with path.open("r", encoding="utf-8") as file:
            backup_data = json.load(file)

    except json.JSONDecodeError as exc:
        raise ValueError("Backup file contains invalid JSON") from exc

    if not isinstance(backup_data, dict):
        raise ValueError("Invalid backup file format")

    return backup_data
