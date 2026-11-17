import json
from pathlib import Path
from securevault.vault.backup import read_backup
from securevault.vault.backup import save_backup
from securevault.exceptions import DecryptionError
from securevault.vault.backup import create_backup, load_backup

# Sample credential (not real account data).
original_credentials = [
    {
        "id": 1,
        "service": "GitHub",
        "label": "Personal",
        "username": "AnilKumar",
        "password": "TestPassword123!",
        "url": "https://github.com",
        "notes": "Test account",
    }
]

backup_password = "BackupTestPassword2026!"

# Encrypt the credentials.
backup_data = create_backup(original_credentials, backup_password)
print("PASS: Backup encrypted")

# Decrypt using the correct password.
restored_credentials = load_backup(backup_data, backup_password)

assert restored_credentials == original_credentials
print("PASS: Backup decrypted correctly")
print("PASS: Credential data matches original")

# Try an incorrect password.
try:
    load_backup(backup_data, "WrongBackupPassword2026!")
    print("FAIL: Wrong password was accepted")
except DecryptionError:
    print("PASS: Wrong backup password rejected")
# Save encrypted backup to a JSON file.
backup_file = "test_securevault_backup.json"

save_backup(backup_file, backup_data)
print("PASS: Encrypted backup saved")

# Read the JSON file back.
with open(backup_file, "r", encoding="utf-8") as file:
    loaded_backup = json.load(file)

print("PASS: JSON backup file loaded")

# Decrypt the saved backup.
file_credentials = load_backup(loaded_backup, backup_password)

assert file_credentials == original_credentials
print("PASS: Saved backup decrypted correctly")

assert Path(backup_file).exists()
print("PASS: Backup file exists")

# Read backup using the new read_backup function.
file_backup_data = read_backup(backup_file)
print("PASS: Backup file read using read_backup")

# Decrypt the file contents.
read_credentials = load_backup(file_backup_data, backup_password)

assert read_credentials == original_credentials
print("PASS: Backup file decrypted using read_backup")
print("\nALL BACKUP TESTS PASSED")
