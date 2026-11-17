from securevault.storage import Storage
from securevault.vault.service import Vault

storage = Storage()

# Create a vault
vault = Vault.create("MyStrongMasterPassword123!")

# Save vault metadata
storage.save_vault_meta(vault.meta)

print("Vault metadata saved!")

# Load vault metadata
meta = storage.load_vault_meta()

print("Vault metadata loaded!")
print("Salt length:", len(meta.salt))
print("KDF time cost:", meta.params.time_cost)
print("KDF memory:", meta.params.memory_kib)
print("KDF parallelism:", meta.params.parallelism)
