from securevault.exceptions import StorageError, VaultError
from securevault.storage import Storage
from securevault.vault.crypto import KdfParams
from securevault.vault.service import Vault

FAST = KdfParams(time_cost=1, memory_kib=64, parallelism=1)


def outcome(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except VaultError as err:
        return f"{type(err).__name__}: {err}"
    return "ok"


db = Storage("securevault_test")
db.reset_schema()


print(outcome(db.load_vault_meta))

vault = Vault.create("correct horse battery", FAST)
db.save_vault_meta(vault.meta)
print(outcome(db.save_vault_meta, vault.meta))

meta = db.load_vault_meta()
print(meta == vault.meta)
unlocked = Vault.unlock(meta, "correct horse battery")
print(repr(unlocked))
print(outcome(Vault.unlock, meta, "wrong password!!"))


def add(service, label, record):
    cred_id = db.reserve_credential_id()
    nonce, ct = unlocked.encrypt_record(record, str(cred_id).encode())
    db.add_credential(cred_id, service, label, nonce, ct)
    return cred_id


id1 = add("github", "personal", {"username": "ravi", "password": "s3cret!"})
id2 = add("github", "work", {"username": "work", "password": "pw2"})
id3 = add("Gmail", "", {"username": "me", "password": "pw3"})
print(id1, id2, id3)

row = db.get_credential(id1)
print(sorted(row))
print(unlocked.decrypt_record(row["nonce"], row["ciphertext"], str(id1).encode()))
print(
    outcome(unlocked.decrypt_record, row["nonce"], row["ciphertext"], str(id2).encode())
)
print(outcome(db.get_credential, 999))

print([(r["id"], r["service"], r["label"]) for r in db.list_credentials()])
print([r["id"] for r in db.search_credentials("GIT")])
print([r["id"] for r in db.search_credentials("work")])
print(db.search_credentials("%"))

n4, c4 = unlocked.encrypt_record(
    {"username": "ravi2", "password": "new"}, str(id1).encode()
)
db.update_credential(id1, "github", "home", n4, c4)
row = db.get_credential(id1)
print(row["label"], row["updated_at"] >= row["created_at"])
print(
    unlocked.decrypt_record(row["nonce"], row["ciphertext"], str(id1).encode())[
        "username"
    ]
)
print(outcome(db.update_credential, 999, "github", "", n4, c4))

db.delete_credential(id2)
print(outcome(db.delete_credential, id2))
print(len(db.list_credentials()))

db.log_event("test_event", "hello")
print([e["event"] for e in db.list_events()])
print([e["event"] for e in db.list_events(2)])
print("s3cret!" in str(db.list_credentials()), "s3cret!" in str(db.list_events()))

try:
    db.add_credential(db.reserve_credential_id(), "x", "", b"n", None)
except StorageError as err:
    print(err, type(err.__cause__).__name__)

try:
    Storage("no_such_db").load_vault_meta()
except StorageError as err:
    print(err, type(err.__cause__).__name__)

print(outcome(Storage("securevault").reset_schema))
print(outcome(KdfParams, 3, 2_000_000, 4))
print(outcome(KdfParams, 11, 65536, 4))

with db._connect() as conn:
    conn.execute("UPDATE vault_meta SET memory_kib = 2000000")
print(outcome(db.load_vault_meta))

print(issubclass(StorageError, VaultError))
