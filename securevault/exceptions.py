class VaultError(Exception):
    """Base exception for all SecureVault application errors."""


class CryptoError(VaultError):
    """Raised when a cryptographic operation cannot be performed."""


class DecryptionError(CryptoError):
    """Raised when decryption or authentication fails."""


class WeakPasswordError(VaultError):
    """Raised when the master password does not meet security requirements."""


class WrongMasterPasswordError(VaultError):
    """Raised when the master password is incorrect."""


class VaultLockedError(VaultError):
    """Raised when an operation is attempted on a locked vault."""
