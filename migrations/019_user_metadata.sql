-- Record of the person-owned user_metadata column. The live migrator is database.Migrate.

ALTER TABLE users ADD COLUMN user_metadata TEXT NOT NULL DEFAULT '{}';
