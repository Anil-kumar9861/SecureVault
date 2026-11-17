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


class Storage:
    def __init__(self, dbname=None):
        self.dbname = dbname

    def _connect(self):
        settings = get_db_settings(self.dbname)

        try:
            return psycopg.connect(**settings, row_factory=dict_row)

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
        settings = get_db_settings(self.dbname)
        database_name = settings["dbname"]

        if not database_name.endswith("_test"):
            raise StorageError("reset_schema is only allowed on test databases")

        try:
            with self._connect() as conn:
                conn.execute("""
                    DROP TABLE IF EXISTS credentials CASCADE;
                    DROP TABLE IF EXISTS vault_meta CASCADE;
                    DROP TABLE IF EXISTS audit_log CASCADE;
                """)

            self.init_schema()

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def save_vault_meta(self, meta: VaultMeta):
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO vault_meta (
                        id,
                        kdf,
                        salt,
                        time_cost,
                        memory_kib,
                        parallelism,
                        check_nonce,
                        check_blob
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
                    """
                    INSERT INTO audit_log (event, detail)
                    VALUES (%s, %s)
                    """,
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
                    SELECT
                        salt,
                        time_cost,
                        memory_kib,
                        parallelism,
                        check_nonce,
                        check_blob
                    FROM vault_meta
                    WHERE id = 1
                    """
                ).fetchone()

                if row is None:
                    raise VaultNotInitializedError("Vault is not initialized")

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
                    INSERT INTO credentials (
                        id,
                        service,
                        label,
                        nonce,
                        ciphertext
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (cred_id, service, label, nonce, ciphertext),
                ).fetchone()

                conn.execute(
                    """
                    INSERT INTO audit_log (event, detail)
                    VALUES (%s, %s)
                    """,
                    ("credential_added", f"id={cred_id}"),
                )

                return row["id"]

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def get_credential(self, cred_id: int) -> dict:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT *
                    FROM credentials
                    WHERE id = %s
                    """,
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
                rows = conn.execute(
                    """
                    SELECT id, service, label, created_at, updated_at
                    FROM credentials
                    ORDER BY id ASC
                    """
                ).fetchall()

                return rows

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def search_credentials(self, query: str) -> list[dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, service, label, created_at, updated_at
                    FROM credentials
                    WHERE POSITION(LOWER(%s) IN LOWER(service)) > 0
                    OR POSITION(LOWER(%s) IN LOWER(label)) > 0
                    ORDER BY id ASC
                    """,
                    (query, query),
                ).fetchall()

                return rows

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
                    """
                        INSERT INTO audit_log (event, detail)
                        VALUES (%s, %s)
                        """,
                    ("credential_updated", f"id={cred_id}"),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def delete_credential(self, cred_id: int) -> None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    DELETE FROM credentials
                    WHERE id = %s
                    RETURNING id
                    """,
                    (cred_id,),
                ).fetchone()

                if row is None:
                    raise CredentialNotFoundError(f"Credential {cred_id} not found")

                conn.execute(
                    """
                    INSERT INTO audit_log (event, detail)
                    VALUES (%s, %s)
                    """,
                    ("credential_deleted", f"id={cred_id}"),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def log_event(self, event: str, detail: str = "") -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log (event, detail)
                    VALUES (%s, %s)
                    """,
                    (event, detail),
                )

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def list_events(self, limit: int = 50) -> list:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("Limit must be a positive integer")

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, at, event, detail
                    FROM (
                        SELECT id, at, event, detail
                        FROM audit_log
                        ORDER BY id DESC
                        LIMIT %s
                    ) AS recent
                    ORDER BY id ASC
                    """,
                    (limit,),
                ).fetchall()

                return rows

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def reserve_credential_id(self) -> int:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                            SELECT nextval(
                                pg_get_serial_sequence('credentials', 'id')
                            ) AS id
                        """)
                    return cur.fetchone()["id"]

        except psycopg.Error as exc:
            raise StorageError("Database error") from exc

    def sync_credential_sequence(self) -> None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT setval(
                            pg_get_serial_sequence('credentials', 'id'),
                            COALESCE(
                                (SELECT MAX(id) FROM credentials),
                                1
                            ),
                            EXISTS(
                                SELECT 1 FROM credentials
                            )
                        )
                    """)

        except psycopg.Error as exc:
            raise StorageError("Failed to synchronize credential sequence") from exc
