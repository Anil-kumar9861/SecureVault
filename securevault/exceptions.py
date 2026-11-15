class VaultError(Exception):
    """Base exception for all SecureVault application errors."""


class CryptoError(VaultError):
    """Raised when a cryptographic operation cannot be performed."""


class DecryptionError(CryptoError):
    """Raised when decryption or authentication fails."""
