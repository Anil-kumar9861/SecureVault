from securevault.exceptions import (
    AmbiguousCredentialError,
    CredentialNotFoundError,
    InvalidInputError,
)
from securevault.vault.service import Vault


class CredentialManager:
    def __init__(self, storage, vault):
        self.storage = storage
        self.vault = vault

    def add(
        self,
        service: str,
        username: str,
        password: str,
        label: str = "",
        url: str = "",
        notes: str = "",
    ) -> int:

        service = service.strip()

        if not service:
            raise InvalidInputError("Service cannot be empty")

        if not password:
            raise InvalidInputError("Password cannot be empty")

        cred_id = self.storage.reserve_credential_id()

        record = {
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }

        aad = str(cred_id).encode()

        nonce, ciphertext = self.vault.encrypt_record(record, aad)

        self.storage.add_credential(
            cred_id,
            service,
            label,
            nonce,
            ciphertext,
        )

        return cred_id

    def get(self, cred_id: int) -> dict:
        row = self.storage.get_credential(cred_id)

        aad = str(cred_id).encode()

        record = self.vault.decrypt_record(
            row["nonce"],
            row["ciphertext"],
            aad,
        )

        return {
            "id": row["id"],
            "service": row["service"],
            "label": row["label"],
            "username": record["username"],
            "password": record["password"],
            "url": record["url"],
            "notes": record["notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_all(self) -> list[dict]:
        rows = self.storage.list_credentials()

        results = []

        for row in rows:
            cred_id = row["id"]
            full_record = self.get(cred_id)

            results.append(
                {
                    "id": cred_id,
                    "service": row["service"],
                    "label": row["label"],
                    "username": full_record["username"],
                }
            )

        return results

    def import_backup_credentials(self, credentials: list[dict]) -> dict:
        """Import backup credentials while skipping duplicates."""

        # Get existing credentials.
        existing = self.list_all()

        # Build a set of existing service and username combinations.
        existing_keys = {
            (
                item["service"].strip().casefold(),
                item["username"].strip().casefold(),
            )
            for item in existing
        }

        prepared = []
        skipped = 0

        for item in credentials:
            if not isinstance(item, dict):
                raise InvalidInputError("Invalid credential in backup")

            service = item.get("service")
            username = item.get("username")
            password = item.get("password")

            if not isinstance(service, str) or not service.strip():
                raise InvalidInputError("Invalid service in backup")

            if not isinstance(username, str):
                raise InvalidInputError("Invalid username in backup")

            if not isinstance(password, str) or not password:
                raise InvalidInputError("Invalid password in backup")

            service = service.strip()

            key = (
                service.casefold(),
                username.strip().casefold(),
            )

            # Skip existing credentials and duplicates within the backup.
            if key in existing_keys:
                skipped += 1
                continue

            label = item.get("label", "")
            url = item.get("url", "")
            notes = item.get("notes", "")

            if not all(isinstance(value, str) for value in (label, url, notes)):
                raise InvalidInputError("Invalid credential data in backup")

            # Generate a new destination database ID.
            cred_id = self.storage.reserve_credential_id()

            record = {
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
            }

            # Encrypt using the destination vault's master key.
            aad = str(cred_id).encode()
            nonce, ciphertext = self.vault.encrypt_record(record, aad)

            prepared.append(
                {
                    "id": cred_id,
                    "service": service,
                    "label": label,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                }
            )

            existing_keys.add(key)

        # Insert all prepared credentials in one transaction.
        imported = self.storage.import_credentials_transaction(prepared)

        return {
            "imported": imported,
            "skipped": skipped,
        }

    def search(self, text: str) -> list[dict]:
        rows = self.storage.search_credentials(text)

        results = []

        for row in rows:
            cred_id = row["id"]
            full_record = self.get(cred_id)

            results.append(
                {
                    "id": cred_id,
                    "service": row["service"],
                    "label": row["label"],
                    "username": full_record["username"],
                }
            )

        return results

    def find(self, identifier: str) -> list[dict]:
        identifier = identifier.strip().casefold()

        results = self.list_all()

        return [item for item in results if item["service"].casefold() == identifier]

    def resolve(self, identifier: str) -> int:
        identifier = identifier.strip()

        if identifier.isdigit():
            return int(identifier)

        matches = self.find(identifier)

        if not matches:
            raise CredentialNotFoundError(f"No credential named {identifier}")

        if len(matches) == 1:
            return matches[0]["id"]

        raise AmbiguousCredentialError(
            f"Several accounts match '{identifier}'. Use an id.",
            matches,
        )

    def edit(self, cred_id: int, **changes) -> None:
        allowed_fields = {
            "service",
            "label",
            "username",
            "password",
            "url",
            "notes",
        }

        for name in changes:
            if name not in allowed_fields:
                raise InvalidInputError(f"Unknown field: {name}")

        if not changes:
            raise InvalidInputError("Nothing to change")

        current = self.get(cred_id)

        service = changes.get("service", current["service"]).strip()
        label = changes.get("label", current["label"])

        record = {
            "username": changes.get("username", current["username"]),
            "password": changes.get("password", current["password"]),
            "url": changes.get("url", current["url"]),
            "notes": changes.get("notes", current["notes"]),
        }

        if not service:
            raise InvalidInputError("Service cannot be empty")

        if not record["password"]:
            raise InvalidInputError("Password cannot be empty")

        aad = str(cred_id).encode()

        nonce, ciphertext = self.vault.encrypt_record(record, aad)

        self.storage.update_credential(
            cred_id,
            service,
            label,
            nonce,
            ciphertext,
        )

    def delete(self, cred_id: int) -> None:
        self.storage.delete_credential(cred_id)

    def change_master_password(self, new_master_password: str) -> None:
        """Re-encrypt all credentials using a new master password."""

        # Create a new vault with a fresh salt and encryption key.
        new_vault = Vault.create(
            new_master_password,
            params=self.vault.meta.params,
        )

        updates = []

        # Read all existing credentials.
        rows = self.storage.list_credentials()

        for row in rows:
            cred_id = row["id"]

            # Retrieve the encrypted credential.
            encrypted_row = self.storage.get_credential(cred_id)

            # Use the credential ID as Additional Authenticated Data.
            aad = str(cred_id).encode()

            # Decrypt using the old vault.
            record = self.vault.decrypt_record(
                encrypted_row["nonce"],
                encrypted_row["ciphertext"],
                aad,
            )

            # Encrypt using the new vault.
            nonce, ciphertext = new_vault.encrypt_record(record, aad)

            updates.append(
                {
                    "id": cred_id,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "updated_at": row["updated_at"],
                }
            )

        # Update all credentials and metadata atomically.
        self.storage.change_master_transaction(
            updates,
            new_vault.export_meta(),
            expected_salt=self.vault.meta.salt,
        )

        # Replace the current vault only after the database update succeeds.
        self.vault = new_vault
