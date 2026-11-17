import hmac
import json
import unicodedata
from dataclasses import dataclass

from securevault.exceptions import (
    DecryptionError,
    VaultLockedError,
    WeakPasswordError,
    WrongMasterPasswordError,
)
from securevault.vault.crypto import (
    KdfParams,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)

MIN_MASTER_LENGTH = 12
MIN_DISTINCT_CHARS = 5

CHECK_PLAINTEXT = b"securevault-check-v1"
CHECK_AAD = b"vault-check"


def validate_master_password(password: str) -> None:
    if not isinstance(password, str) or not password.strip():
        raise WeakPasswordError("Master password cannot be empty")
    normalized = unicodedata.normalize("NFKC", password)

    if len(normalized) < MIN_MASTER_LENGTH:
        raise WeakPasswordError("Master password must be at least 12 characters")

    if len(set(normalized)) < MIN_DISTINCT_CHARS:
        raise WeakPasswordError("Master password is too repetitive")


@dataclass(frozen=True)
class VaultMeta:
    salt: bytes
    params: KdfParams
    check_nonce: bytes
    check_blob: bytes


class Vault:
    def __init__(self, meta: VaultMeta, key: bytes):
        self.meta = meta
        self._key = key

    @classmethod
    def create(cls, master_password: str, params: KdfParams = KdfParams()) -> "Vault":

        validate_master_password(master_password)

        salt = generate_salt()

        key = derive_key(master_password, salt, params)

        check_nonce, check_blob = encrypt(key, CHECK_PLAINTEXT, CHECK_AAD)

        meta = VaultMeta(
            salt=salt, params=params, check_nonce=check_nonce, check_blob=check_blob
        )

        return cls(meta, key)

    @classmethod
    def unlock(cls, meta: VaultMeta, master_password: str) -> "Vault":

        if not isinstance(master_password, str) or not master_password.strip():
            raise WrongMasterPasswordError("Wrong master password")

        key = derive_key(master_password, meta.salt, meta.params)

        try:
            plaintext = decrypt(key, meta.check_nonce, meta.check_blob, CHECK_AAD)
        except DecryptionError as exc:
            raise WrongMasterPasswordError("Wrong master password") from exc

        if not hmac.compare_digest(plaintext, CHECK_PLAINTEXT):
            raise WrongMasterPasswordError("Wrong master password")

        return cls(meta, key)

    def export_meta(self) -> VaultMeta:
        """Return the vault metadata for database storage."""
        return self.meta

    def encrypt_record(self, record: dict, aad: bytes) -> tuple[bytes, bytes]:
        if self._key is None:
            raise VaultLockedError("Vault is locked")

        plaintext = json.dumps(record, sort_keys=True).encode("utf-8")

        nonce, ciphertext = encrypt(self._key, plaintext, aad)

        return nonce, ciphertext

    def decrypt_record(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> dict:
        if self._key is None:
            raise VaultLockedError("Vault is locked")

        plaintext = decrypt(self._key, nonce, ciphertext, aad)

        record = json.loads(plaintext.decode("utf-8"))

        return record

    def lock(self) -> None:
        self._key = None

    def __repr__(self) -> str:
        if self._key is None:
            return "<Vault locked>"

        return "<Vault unlocked>"
