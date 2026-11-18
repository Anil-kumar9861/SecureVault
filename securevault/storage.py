from datetime import date
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from securevault.config import get_db_settings
from securevault.exceptions import (
    CredentialNotFoundError,
    StorageError,
    VaultAlreadyExistsError,
    VaultNotInitializedError,
)
from securevault.vault.crypto import KdfParams
from securevault.vault.service import VaultMeta

# Columns returned for a credential row. Listed explicitly (no SELECT *), so a
# column added to the table later can never leak out by accident.
CREDENTIAL_COLUMNS = "id, service, label, nonce, ciphertext, created_at, updated_at"


class Storage:
    def __init__(self, dbname=None):
        self.dbname = dbname

    def _connect(self):
        settings = get_db_settings(self.dbname)

        try:
            return psycopg.connect(**settings, row_factory=dict_row, connect_timeout=5)

        except psycopg.OperationalError as exc:
            raise StorageError("Could not connect to the database") from exc

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def init_schema(self):
        schema_path = Path(__file__).parent.parent / "schema.sql"

        try:
            sql = schema_path.read_text(encoding="utf-8")

            with self._connect() as conn:
                conn.execute(sql)

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

        except OSError as exc:
            raise StorageError("Could not read schema file") from exc

    def reset_schema(self):
        # Check the database name BEFORE connecting, so a real database can
        # never be wiped by mistake.
        settings = get_db_settings(self.dbname)
        database_name = settings["dbname"]

        if not database_name.endswith("_test"):
            raise StorageError("reset_schema is only allowed on test databases")

        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    DROP TABLE IF EXISTS credentials CASCADE;
                    DROP TABLE IF EXISTS vault_meta CASCADE;
                    DROP TABLE IF EXISTS audit_log CASCADE;
                    """
                )

            self.init_schema()

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def save_vault_meta(self, meta: VaultMeta) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO vault_meta (
                        id, kdf, salt, time_cost, memory_kib,
                        parallelism, check_nonce, check_blob
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        1,
                        "argon2id",
                        meta.salt,
                        meta.params.time_cost,
                        meta.params.memory_kib,
                        meta.params.parallelism,
                        meta.check_nonce,
                        meta.check_blob,
                    ),
                )

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("vault_created", ""),
                )

        except psycopg.errors.UniqueViolation as exc:
            raise VaultAlreadyExistsError("Vault already exists") from exc

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def load_vault_meta(self) -> VaultMeta:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT salt, time_cost, memory_kib, parallelism,
                           check_nonce, check_blob
                    FROM vault_meta
                    WHERE id = 1
                    """
                ).fetchone()

                if row is None:
                    raise VaultNotInitializedError("Vault is not initialized")

                # KdfParams validates the stored numbers, so a tampered row
                # (for example a huge memory value) is rejected here.
                params = KdfParams(
                    time_cost=row["time_cost"],
                    memory_kib=row["memory_kib"],
                    parallelism=row["parallelism"],
                )

                return VaultMeta(
                    salt=row["salt"],
                    params=params,
                    check_nonce=row["check_nonce"],
                    check_blob=row["check_blob"],
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def reserve_credential_id(self) -> int:
        # The id is needed BEFORE encrypting, because it is used as the
        # associated data (aad) that binds a ciphertext to its own row.
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT nextval(pg_get_serial_sequence('credentials', 'id')) AS id"
                ).fetchone()
                return row["id"]

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def add_credential(
        self,
        cred_id: int,
        service: str,
        label: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> int:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    INSERT INTO credentials (id, service, label, nonce, ciphertext)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (cred_id, service, label, nonce, ciphertext),
                ).fetchone()

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("credential_added", f"id={cred_id}"),
                )

                return row["id"]

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def get_credential(self, cred_id: int) -> dict:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    f"SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE id = %s",
                    (cred_id,),
                ).fetchone()

                if row is None:
                    raise CredentialNotFoundError(f"Credential {cred_id} not found")

                return row

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def list_credentials(self) -> list[dict]:
        try:
            with self._connect() as conn:
                return conn.execute(
                    f"SELECT {CREDENTIAL_COLUMNS} FROM credentials ORDER BY id ASC"
                ).fetchall()

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def search_credentials(self, query: str) -> list[dict]:
        # POSITION() treats % and _ as plain characters, so no escaping is needed.
        try:
            with self._connect() as conn:
                return conn.execute(
                    f"""
                    SELECT {CREDENTIAL_COLUMNS}
                    FROM credentials
                    WHERE POSITION(LOWER(%s) IN LOWER(service)) > 0
                       OR POSITION(LOWER(%s) IN LOWER(label)) > 0
                    ORDER BY id ASC
                    """,
                    (query, query),
                ).fetchall()

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def update_credential(
        self,
        cred_id: int,
        service: str,
        label: str,
        nonce: bytes,
        ciphertext: bytes,
    ) -> None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    UPDATE credentials
                    SET service = %s,
                        label = %s,
                        nonce = %s,
                        ciphertext = %s,
                        updated_at = now()
                    WHERE id = %s
                    RETURNING id
                    """,
                    (service, label, nonce, ciphertext, cred_id),
                ).fetchone()

                if row is None:
                    raise CredentialNotFoundError(f"Credential {cred_id} not found")

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("credential_updated", f"id={cred_id}"),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def delete_credential(self, cred_id: int) -> None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "DELETE FROM credentials WHERE id = %s RETURNING id",
                    (cred_id,),
                ).fetchone()

                if row is None:
                    raise CredentialNotFoundError(f"Credential {cred_id} not found")

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("credential_deleted", f"id={cred_id}"),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def log_event(self, event: str, detail: str = "") -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    (event, detail),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def list_events(
        self,
        limit: int = 50,
        event: str | None = None,
        since: date | None = None,
        until: date | None = None,
    ) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")

        if event is not None:
            if not isinstance(event, str) or not event.strip():
                raise ValueError("event must be a non-empty string")
            event = event.strip()

        if since is not None and not isinstance(since, date):
            raise ValueError("since must be a valid date")

        if until is not None and not isinstance(until, date):
            raise ValueError("until must be a valid date")

        if since is not None and until is not None and since > until:
            raise ValueError("since date cannot be after until date")

        try:
            with self._connect() as conn:
                conditions = []
                params = []

                if event is not None:
                    conditions.append("event = %s")
                    params.append(event)

                if since is not None:
                    conditions.append("at::date >= %s")
                    params.append(since)

                if until is not None:
                    conditions.append("at::date <= %s")
                    params.append(until)

                where_clause = ""

                if conditions:
                    where_clause = "WHERE " + " AND ".join(conditions)

                query = f"""
                    SELECT id, at, event, detail FROM (
                        SELECT id, at, event, detail
                        FROM audit_log
                        {where_clause}
                        ORDER BY id DESC
                        LIMIT %s
                    ) AS recent
                    ORDER BY id ASC
                """

                params.append(limit)

                return conn.execute(query, params).fetchall()

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def import_credentials_transaction(self, credentials: list[dict]) -> int:
        """Insert several already-encrypted credentials in ONE transaction."""
        if not credentials:
            return 0

        try:
            with self._connect() as conn:
                for item in credentials:
                    conn.execute(
                        """
                        INSERT INTO credentials (id, service, label, nonce, ciphertext)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            item["id"],
                            item["service"],
                            item["label"],
                            item["nonce"],
                            item["ciphertext"],
                        ),
                    )

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("credentials_imported", f"count={len(credentials)}"),
                )

            return len(credentials)

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def change_master_transaction(
        self, updates: list[dict], meta: VaultMeta, expected_salt: bytes
    ) -> None:
        """Re-key the vault: every credential plus vault_meta, all or nothing.

        Each item in `updates` has: id, nonce, ciphertext, updated_at, where
        `updated_at` is the value that was read before re-encrypting. If anything
        changed in the meantime, the whole operation is refused.
        """
        try:
            with self._connect() as conn:
                # Block other writers to credentials until this transaction ends.
                conn.execute("LOCK TABLE credentials IN EXCLUSIVE MODE")

                # Every credential in the table must be part of the update.
                current_ids = {
                    row["id"]
                    for row in conn.execute("SELECT id FROM credentials").fetchall()
                }
                wanted_ids = [item["id"] for item in updates]
                if (
                    len(wanted_ids) != len(set(wanted_ids))
                    or set(wanted_ids) != current_ids
                ):
                    raise StorageError(
                        "Credentials changed while changing the master password"
                    )

                for item in updates:
                    row = conn.execute(
                        """
                        UPDATE credentials
                        SET nonce = %s, ciphertext = %s
                        WHERE id = %s AND updated_at = %s
                        RETURNING id
                        """,
                        (
                            item["nonce"],
                            item["ciphertext"],
                            item["id"],
                            item["updated_at"],
                        ),
                    ).fetchone()

                    if row is None:
                        raise StorageError(
                            "Credentials changed while changing the master password"
                        )

                # Only switch the vault if it is still the one we started from.
                row = conn.execute(
                    """
                    UPDATE vault_meta
                    SET kdf = %s, salt = %s, time_cost = %s, memory_kib = %s,
                        parallelism = %s, check_nonce = %s, check_blob = %s
                    WHERE id = 1 AND salt = %s
                    RETURNING id
                    """,
                    (
                        "argon2id",
                        meta.salt,
                        meta.params.time_cost,
                        meta.params.memory_kib,
                        meta.params.parallelism,
                        meta.check_nonce,
                        meta.check_blob,
                        expected_salt,
                    ),
                ).fetchone()

                if row is None:
                    raise StorageError(
                        "The vault changed while changing the master password"
                    )

                conn.execute(
                    "INSERT INTO audit_log (event, detail) VALUES (%s, %s)",
                    ("master_password_changed", f"credentials={len(updates)}"),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc
