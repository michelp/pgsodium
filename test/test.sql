-- \set ECHO none
-- \set QUIET 1

-- \pset format unaligned
-- \pset tuples_only true
-- \pset pager

-- \set ON_ERROR_ROLLBACK 1
-- \set ON_ERROR_STOP true
-- \set QUIET 1

CREATE EXTENSION IF NOT EXISTS pgtap;
CREATE SCHEMA pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

SET search_path = pgsodium, public;

SELECT EXISTS (SELECT * FROM pg_settings
	WHERE name = 'shared_preload_libraries'
	AND setting ilike '%pgsodium%') serverkeys \gset

\ir random.sql
\ir secretbox.sql
\ir secretstream.sql
\ir stream.sql
\ir aead.sql
\ir auth.sql
\ir hash.sql
\ir box.sql
\ir sign.sql
\ir pwhash.sql
\ir kdf.sql
\ir kx.sql
\ir sha2.sql
\ir hmac.sql
\ir derive.sql
\ir signcrypt.sql
\ir helpers.sql
\ir tce.sql
