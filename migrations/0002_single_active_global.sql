CREATE UNIQUE INDEX IF NOT EXISTS credentials_single_active_global
	ON credentials(type)
	WHERE type = 'global' AND status = 'active';
