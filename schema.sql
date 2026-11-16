
CREATE TABLE IF NOT EXISTS vault_meta (
    id           SMALLINT PRIMARY KEY CHECK (id = 1),
    kdf          TEXT NOT NULL DEFAULT 'argon2id',
    salt         BYTEA NOT NULL,
    time_cost    INT NOT NULL,
    memory_kib   INT NOT NULL,
    parallelism  INT NOT NULL,
    check_nonce  BYTEA NOT NULL,
    check_blob   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credentials (
    id          SERIAL PRIMARY KEY,
    service     TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    nonce       BYTEA NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS credentials_service_idx
ON credentials (service);

CREATE TABLE IF NOT EXISTS audit_log (
    id      SERIAL PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event   TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT ''
);
