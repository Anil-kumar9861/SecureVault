import unicodedata
from dataclasses import dataclass

from securevault.exceptions import WeakPasswordError
from securevault.vault.crypto import KdfParams

MIN_MASTER_LENGTH = 12
MIN_DISTINCT_CHARS = 5

CHECK_PLAINTEXT = b"securevault-check-v1"
CHECK_ADD = b"vault-check"


def validate_master_password(password: str) -> None:
    if not isinstance(password, str) or not password.strip():
        raise WeakPasswordError("Master password connot be empty")
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
