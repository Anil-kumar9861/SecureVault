from securevault.storage import Storage
from securevault.vault.credentials import CredentialManager
from securevault.vault.service import Vault

db = Storage("securevault_test")
db.reset_schema()

print("Test database reset successfully!")

MASTER = "correct horse battery"

vault = Vault.create(MASTER)
db.save_vault_meta(vault.meta)

loaded_meta = db.load_vault_meta()
unlocked = Vault.unlock(loaded_meta, MASTER)

manager = CredentialManager(db, unlocked)

print("Vault initialized and unlocked!")
print("CredentialManager created successfully!")


cred_id = manager.add(
    service="GitHub",
    username="ravi",
    password="s3cret!",
    label="Personal",
    url="https://github.com",
    notes="My personal GitHub account",
)

print("Credential added successfully!")
print("Credential ID:", cred_id)


credential = manager.get(cred_id)

print("\nRetrieved credential:")
print("ID:", credential["id"])
print("Service:", credential["service"])
print("Label:", credential["label"])
print("Username:", credential["username"])
print("Password:", credential["password"])
print("URL:", credential["url"])
print("Notes:", credential["notes"])


credentials = manager.list_all()

print("\nCredential list:")

for item in credentials:
    print(item)

print("\nPassword included:", any("password" in item for item in credentials))


manager.add(
    service="Gmail",
    username="ravi@gmail.com",
    password="gmail123",
    label="Personal",
)

manager.add(
    service="GitHub",
    username="work-user",
    password="work123",
    label="Office",
)

print("\nSearch results for GitHub:")

results = manager.search("GitHub")

for item in results:
    print(item)


print("\nFind GitHub accounts:")

matches = manager.find("github")

for item in matches:
    print(item)


print("\nResolve tests:")

print("Resolve ID 1:", manager.resolve("1"))
print("Resolve Gmail:", manager.resolve("Gmail"))

try:
    manager.resolve("GitHub")
except Exception as exc:
    print(type(exc).__name__, ":", exc)

try:
    manager.resolve("Nothing")
except Exception as exc:
    print(type(exc).__name__, ":", exc)


print("\nEdit test:")

manager.edit(
    1,
    username="ravi_updated",
    password="new_secret",
    label="Updated Personal",
)

updated = manager.get(1)

print("Username:", updated["username"])
print("Password:", updated["password"])
print("Label:", updated["label"])

print("\nDelete test:")

manager.delete(2)

print("Remaining credentials:")

for item in manager.list_all():
    print(item)


print("\nValidation tests:")

# 1. Empty service
try:
    manager.add("", "user", "password")
except Exception as exc:
    print(type(exc).__name__, ":", exc)

# 2. Empty password
try:
    manager.add("Facebook", "user", "")
except Exception as exc:
    print(type(exc).__name__, ":", exc)

# 3. Unknown edit field
try:
    manager.edit(1, email="test@gmail.com")
except Exception as exc:
    print(type(exc).__name__, ":", exc)

# 4. No changes
try:
    manager.edit(1)
except Exception as exc:
    print(type(exc).__name__, ":", exc)

# 5. Missing credential
try:
    manager.get(99)
except Exception as exc:
    print(type(exc).__name__, ":", exc)

# 6. Password must not appear in list
print(
    "Password exposed in list:", any("password" in item for item in manager.list_all())
)

# 7. Audit log
print("Audit events:", [e["event"] for e in db.list_events()])
