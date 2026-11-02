-- Record of role and direct scope grants. The live migrator is database.Migrate.

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_scopes (
    role_id TEXT NOT NULL,
    resource_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (role_id, resource_uri, scope)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id, org_id)
);

CREATE TABLE IF NOT EXISTS user_scopes (
    user_id TEXT NOT NULL,
    resource_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, resource_uri, scope, org_id)
);
