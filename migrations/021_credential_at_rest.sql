-- Record of hashed bearers and access-token ids.
-- The live migrator is database.Migrate.

ALTER TABLE access_tokens ADD COLUMN id TEXT;
CREATE INDEX IF NOT EXISTS idx_access_tokens_id ON access_tokens(id);
