CREATE TABLE IF NOT EXISTS service_state (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
	name TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS environments (
	project TEXT NOT NULL,
	name TEXT NOT NULL,
	is_default INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL,
	PRIMARY KEY (project, name),
	FOREIGN KEY (project) REFERENCES projects(name)
);

CREATE TABLE IF NOT EXISTS credentials (
	identifier TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	project TEXT,
	environment TEXT,
	auth_public_key TEXT NOT NULL,
	decrypt_public_key TEXT,
	status TEXT NOT NULL,
	issued_at INTEGER NOT NULL,
	expires_at INTEGER,
	issued_by TEXT NOT NULL,
	revoked_at INTEGER,
	revoked_by TEXT,
	revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS credentials_scope
	ON credentials(project, environment, type, status);

CREATE TABLE IF NOT EXISTS request_nonces (
	credential_id TEXT NOT NULL,
	nonce TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY (credential_id, nonce)
);

CREATE INDEX IF NOT EXISTS request_nonces_expiry
	ON request_nonces(expires_at);

CREATE TABLE IF NOT EXISTS schema_manifests (
	project TEXT NOT NULL,
	digest TEXT NOT NULL,
	manifest TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL,
	PRIMARY KEY (project, digest)
);
