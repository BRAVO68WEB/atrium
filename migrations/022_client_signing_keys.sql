-- Record only. The running server applies the same changes in database.Migrate.
-- This file is not executed on startup.

CREATE TABLE IF NOT EXISTS client_signing_keys (
    client_id TEXT NOT NULL,
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    status TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retire_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_client_signing_keys_client ON client_signing_keys(client_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_client_signing_keys_active
    ON client_signing_keys(client_id) WHERE status = 'active';
