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
db.init_schema()

print(outcome(db.load_vault_meta))

vault = Vault.create("correct horse battery", FAST)
db.save_vault_meta(vault.meta)
print(outcome(db.save_vault_meta, vault.meta))

meta = db.load_vault_meta()
print(meta == vault.meta)
unlocked = Vault.unlock(meta, "correct horse battery")
print(repr(unlocked))
print(outcome(Vault.unlock, meta, "wrong password!!"))

n1, c1 = unlocked.encrypt_record({"username": "ravi", "password": "s3cret!"}, b"x")
id1 = db.add_credential("github", "personal", n1, c1)
n2, c2 = unlocked.encrypt_record({"username": "work", "password": "pw2"}, b"x")
id2 = db.add_credential("github", "work", n2, c2)
n3, c3 = unlocked.encrypt_record({"username": "me", "password": "pw3"}, b"x")
id3 = db.add_credential("Gmail", "", n3, c3)
print(id1, id2, id3)

row = db.get_credential(id1)
print(sorted(row))
print(unlocked.decrypt_record(row["nonce"], row["ciphertext"], b"x"))
print(outcome(db.get_credential, 999))

print([(r["id"], r["service"], r["label"]) for r in db.list_credentials()])
print([r["id"] for r in db.search_credentials("GIT")])
print([r["id"] for r in db.search_credentials("work")])
print(db.search_credentials("%"))

n4, c4 = unlocked.encrypt_record({"username": "ravi2", "password": "new"}, b"x")
db.update_credential(id1, n4, c4, label="home")
row = db.get_credential(id1)
print(row["label"], row["updated_at"] >= row["created_at"])
print(unlocked.decrypt_record(row["nonce"], row["ciphertext"], b"x")["username"])
print(outcome(db.update_credential, 999, n4, c4))

db.delete_credential(id2)
print(outcome(db.delete_credential, id2))
print(len(db.list_credentials()))

db.log_event("test_event", "hello")
print([e["event"] for e in db.list_events()])
print("s3cret!" in str(db.list_credentials()), "s3cret!" in str(db.list_events()))

try:
    db.add_credential("x", "", b"n", None)
except StorageError as err:
    print(err, type(err.__cause__).__name__)

try:
    Storage("no_such_db").load_vault_meta()
except StorageError as err:
    print(err, type(err.__cause__).__name__)

print(outcome(Storage("securevault").reset_schema))
print(outcome(KdfParams, 3, 2_000_000, 4))
print(outcome(KdfParams, 11, 65536, 4))
print(issubclass(StorageError, VaultError))
