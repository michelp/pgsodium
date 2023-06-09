\unset ECHO
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager off

\set ON_ERROR_ROLLBACK 1
\set ON_ERROR_STOP on

SET client_min_messages TO WARNING;

SELECT EXISTS (SELECT * FROM pg_settings
    WHERE name = 'shared_preload_libraries'
    AND setting ilike '%pgsodium%') serverkeys \gset

CREATE EXTENSION IF NOT EXISTS pgtap;

SELECT diag('Existing pgsodium version: '|| extversion)
FROM pg_catalog.pg_extension
WHERE extname = 'pgsodium';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pgsodium') THEN
        EXECUTE 'CREATE EXTENSION pgsodium';
    ELSE
        EXECUTE 'ALTER EXTENSION pgsodium UPDATE';
    END IF;
END
$$;

SELECT diag('Installed or updated version of pgsodium: '|| extversion)
FROM pg_catalog.pg_extension
WHERE extname = 'pgsodium';

SELECT diag('Running tests on ' || pg_catalog.version());

SELECT diag(format('Parameter %s = %s', name, setting))
FROM pg_settings
WHERE name IN ('shared_preload_libraries', 'pgsodium.getkey_script');

SELECT diag('Running tests in database ' || current_database());

BEGIN;
CREATE ROLE bobo with login password 'foo';

SELECT * FROM no_plan();

\ir pgsodium_schema.sql

SET search_path = pgsodium, public;

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
\ir tce_rls.sql
\ir keys.sql

SELECT * FROM finish();

ROLLBACK;
