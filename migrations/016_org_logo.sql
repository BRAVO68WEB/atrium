-- Record only. database.Migrate applies the same change.
ALTER TABLE organizations ADD COLUMN logo_url TEXT NOT NULL DEFAULT '';
