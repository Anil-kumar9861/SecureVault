import secrets
import unicodedata
from dataclasses import dataclass

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securevault.exceptions import CryptoError, DecryptionError


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_kib: int = 65536
    parallelism: int = 4

    def __post_init__(self):

        values = (self.time_cost, self.memory_kib, self.parallelism)

        for value in values:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CryptoError("KDF parameters must be positive integers")

        if self.memory_kib < 8 * self.parallelism:
            raise CryptoError("Insufficient memory for Argon2")

        if self.time_cost > 10 or self.memory_kib > 1_048_576 or self.parallelism > 16:
            raise CryptoError("KDF parameters out of allowed range")


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

    except HashingError as exc:
        raise CryptoError("Key derivation failed") from exc


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:

    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError("Encryption key must be exactly 32 bytes")

    nonce = secrets.token_bytes(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def decrypt(key, nonce, ciphertext, aad=b""):
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError("Decryption key must be exactly 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoError("Nonce must be exactly 12 bytes")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Decryption failed") from exc
