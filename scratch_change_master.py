from securevault.exceptions import WrongMasterPasswordError
from securevault.storage import Storage
from securevault.vault.credentials import CredentialManager
from securevault.vault.crypto import KdfParams
from securevault.vault.service import Vault

# Fast parameters for testing only.
FAST = KdfParams(
    time_cost=1,
    memory_kib=64,
    parallelism=1,
)

OLD_PASSWORD = "OldTestMaster2026!"
NEW_PASSWORD = "NewTestMaster2026!"


# 1. Reset only the test database.
storage = Storage("securevault_test")
storage.reset_schema()
print("PASS: Test database reset")

# 2. Create the original test vault.
old_vault = Vault.create(OLD_PASSWORD, params=FAST)
storage.save_vault_meta(old_vault.export_meta())

manager = CredentialManager(storage, old_vault)

# 3. Add two test credentials.
id1 = manager.add(
    service="GitHub",
    username="testuser",
    password="github-test-password",
)

id2 = manager.add(
    service="Gmail",
    username="testemail",
    password="gmail-test-password",
)

print("PASS: Two credentials added")

# Keep the original metadata for testing.
# 4. Confirm the old password works before changing it.
old_meta = storage.load_vault_meta()
Vault.unlock(old_meta, OLD_PASSWORD)
print("PASS: Old master password accepted before change")

# 5. Change the master password only once.
manager.change_master_password(NEW_PASSWORD)
print("PASS: Master password changed")

# 6. Load updated metadata.
new_meta = storage.load_vault_meta()

# Verify old password is rejected.
try:
    Vault.unlock(new_meta, OLD_PASSWORD)
    raise AssertionError("Old password still works!")
except WrongMasterPasswordError:
    print("PASS: Old master password rejected")

# Verify new password is accepted.
new_vault = Vault.unlock(new_meta, NEW_PASSWORD)
print("PASS: New master password accepted")

# 7. Verify both credentials are still readable.
new_manager = CredentialManager(storage, new_vault)

github = new_manager.get(id1)
gmail = new_manager.get(id2)

assert github["password"] == "github-test-password"
assert gmail["password"] == "gmail-test-password"

assert github["username"] == "testuser"
assert gmail["username"] == "testemail"

print("PASS: GitHub credential decrypted")
print("PASS: Gmail credential decrypted")

print("\nALL MASTER PASSWORD TESTS PASSED")
