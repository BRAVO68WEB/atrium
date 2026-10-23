-- Record of the push delivery-mode column. The live migrator is database.Migrate.

ALTER TABLE push_auth_requests ADD COLUMN delivery_mode TEXT;
