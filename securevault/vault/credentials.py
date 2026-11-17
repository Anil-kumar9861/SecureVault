from securevault.exceptions import (
    AmbiguousCredentialError,
    CredentialNotFoundError,
    InvalidInputError,
)


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
