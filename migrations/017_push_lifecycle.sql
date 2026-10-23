-- Record of push-device lifecycle columns. The live migrator is database.Migrate.

ALTER TABLE push_devices ADD COLUMN previous_jwk TEXT;
ALTER TABLE push_devices ADD COLUMN previous_jkt TEXT;
ALTER TABLE push_devices ADD COLUMN grace_until TEXT;
ALTER TABLE push_devices ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0;
