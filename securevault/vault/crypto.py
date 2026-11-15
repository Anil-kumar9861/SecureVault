import secrets
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securevault.exceptions import CryptoError, DecryptionError


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 1
    memory_kib: int = 8192
    parallelism: int = 1

    def __post_init__(self):

        values = (self.time_cost, self.memory_kib, self.parallelism)

        for value in values:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CryptoError("KDF parameters must be positive integers")

        if self.memory_kib < 8 * self.parallelism:
            raise CryptoError("Insufficent memory for Argon2")


def generate_salt() -> bytes:
    return secrets.token_bytes(16)


def derive_key(password: str, salt: bytes, params: KdfParams = KdfParams()) -> bytes:

    if not password:
        raise CryptoError("Password cannot be empty")

    if not isinstance(salt, bytes) or len(salt) < 16:
        raise CryptoError("Salt must contain at least 16 bytes")

    normalized_password = unicodedata.normalize("NFKC", password)

    password_bytes = normalized_password.encode("utf-8")

    try:
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            hash_len=32,
            type=Type.ID,
        )

        return key

    except Exception as exc:
        raise CryptoError("Key derivation failed") from exc


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:

    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError("Encryption key must be exactly 32 bytes")

    nonce = secrets.token_bytes(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:

    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError("Decryption key must be exactly 32 bytes")

    try:
        aes = AESGCM(key)

        plaintext = aes.decrypt(nonce, ciphertext, aad)

        return plaintext

    except Exception as exc:
        raise DecryptionError("Decryption failed") from exc
