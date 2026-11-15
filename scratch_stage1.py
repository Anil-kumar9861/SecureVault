from securevault.exceptions import CryptoError, DecryptionError, VaultError
from securevault.vault.crypto import (
    KdfParams,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)

FAST = KdfParams(time_cost=1, memory_kib=64, parallelism=1)  # for tests only


def fails(func, *args):
    try:
        func(*args)
    except DecryptionError as err:
        return str(err)
    return "no error"


def invalid(func, *args):
    try:
        func(*args)
    except CryptoError:
        return "CryptoError"
    return "no error"


salt = generate_salt()
print(len(salt), generate_salt() != salt)

key = derive_key("correct horse battery", salt, FAST)
print(len(key))
print(key == derive_key("correct horse battery", salt, FAST))
print(key == derive_key("correct horse battery", generate_salt(), FAST))
print(key == derive_key("another password", salt, FAST))
print(derive_key("e\u0301", salt, FAST) == derive_key("\u00e9", salt, FAST))

nonce, ct = encrypt(key, b"hello vault")
print(len(nonce), len(ct))
print(decrypt(key, nonce, ct))
nonce2, ct2 = encrypt(key, b"hello vault")
print(nonce != nonce2, ct != ct2)

wrong_key = derive_key("wrong password", salt, FAST)
print(fails(decrypt, wrong_key, nonce, ct))
flipped = bytes([ct[0] ^ 1]) + ct[1:]
print(fails(decrypt, key, nonce, flipped))
bad_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
print(fails(decrypt, key, bad_nonce, ct))

n3, c3 = encrypt(key, b"secret", b"github")
print(decrypt(key, n3, c3, b"github"))
print(fails(decrypt, key, n3, c3, b"gitlab"))

print(invalid(derive_key, "", salt, FAST))
print(invalid(derive_key, "pw", b"short", FAST))
print(invalid(encrypt, b"x" * 16, b"data"))
print(invalid(KdfParams, 3, 4, 1))
print(invalid(KdfParams, 0, 64, 1))

print(issubclass(DecryptionError, VaultError), issubclass(DecryptionError, CryptoError))

try:
    decrypt(wrong_key, nonce, ct)
except DecryptionError as err:
    print(err.__cause__ is not None, "wrong password" in str(err))
