class VaultError(Exception):
    """Base exception for all SecureVault application errors."""


# Cryptography errors
class CryptoError(VaultError):
    """Raised when a cryptographic operation cannot be performed."""


class DecryptionError(CryptoError):
    """Raised when decryption or authentication fails."""


# Password errors
class WeakPasswordError(VaultError):
    """Raised when the master password is too weak."""


class WrongMasterPasswordError(VaultError):
    """Raised when the master password is incorrect."""


class VaultLockedError(VaultError):
    """Raised when an operation is attempted on a locked vault."""


# Configuration and database errors
class ConfigError(VaultError):
    """Raised when application configuration is invalid."""


class StorageError(VaultError):
    """Raised when database storage operations fail."""


class VaultNotInitializedError(VaultError):
    """Raised when the vault has not been initialized."""


class VaultAlreadyExistsError(VaultError):
    """Raised when attempting to create an existing vault."""


class CredentialNotFoundError(VaultError):
    """Raised when a requested credential does not exist."""


class InvalidInputError(VaultError):
    """Raised when user input is invalid."""


class AmbiguousCredentialError(VaultError):
    """Raised when multiple credentials match an identifier."""

    def __init__(self, message, matches=None):
        super().__init__(message)
        self.matches = matches or []
