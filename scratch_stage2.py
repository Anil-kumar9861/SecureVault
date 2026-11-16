from securevault.exceptions import (
    VaultError,
    VaultLockedError,
    WeakPasswordError,
    WrongMasterPasswordError,
)
from securevault.vault.crypto import KdfParams
from securevault.vault.service import Vault, VaultMeta, validate_master_password

FAST = KdfParams(time_cost=1, memory_kib=64, parallelism=1)


def outcome(func, *args):
    try:
        func(*args)
    except VaultError as err:
        return f"{type(err).__name__}: {err}"
    return "ok"


print(outcome(validate_master_password, ""))
print(outcome(validate_master_password, "   "))
print(outcome(validate_master_password, None))
print(outcome(validate_master_password, "short"))
print(outcome(validate_master_password, "aaaaaaaaaaaaaaaa"))
print(outcome(validate_master_password, "correct horse battery"))

vault = Vault.create("correct horse battery", FAST)
print(
    isinstance(vault.meta, VaultMeta), len(vault.meta.salt), len(vault.meta.check_nonce)
)
print(outcome(Vault.create, "short", FAST))
print(vault.meta.params == FAST)

same = Vault.unlock(vault.meta, "correct horse battery")
print(isinstance(same, Vault))
print(outcome(Vault.unlock, vault.meta, "wrong password!!"))
print(outcome(Vault.unlock, vault.meta, ""))

bad_blob = bytes([vault.meta.check_blob[0] ^ 1]) + vault.meta.check_blob[1:]
bad = VaultMeta(vault.meta.salt, vault.meta.params, vault.meta.check_nonce, bad_blob)
print(outcome(Vault.unlock, bad, "correct horse battery"))

record = {"username": "ravi", "password": "s3cret!", "url": "https://github.com"}
nonce, ct = vault.encrypt_record(record, b"github")
print(same.decrypt_record(nonce, ct, b"github") == record)
print(outcome(vault.decrypt_record, nonce, ct, b"gitlab"))

other = Vault.create("correct horse battery", FAST)
print(
    other.meta.salt != vault.meta.salt, other.meta.check_blob != vault.meta.check_blob
)
print(outcome(other.decrypt_record, nonce, ct, b"github"))

print(repr(vault), repr(same))
print(vault._key.hex() in repr(vault), repr(vault._key) in repr(vault))

same.lock()
print(repr(same))
print(outcome(same.encrypt_record, record, b"x"))
print(outcome(same.decrypt_record, nonce, ct, b"github"))

try:
    vault.meta.salt = b"x"
except Exception as err:
    print(type(err).__name__)

print(
    issubclass(WeakPasswordError, VaultError),
    issubclass(WrongMasterPasswordError, VaultError),
    issubclass(VaultLockedError, VaultError),
)
