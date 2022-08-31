\set ECHO none
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager

\set ON_ERROR_ROLLBACK 1
\set ON_ERROR_STOP on
-- \set QUIET 1

CREATE EXTENSION IF NOT EXISTS pgtap;

BEGIN;
SELECT plan(1);
CREATE SCHEMA bogus;
SELECT throws_ok($$CREATE EXTENSION pgsodium WITH SCHEMA bogus$$,
                 '0A000', 'extension "pgsodium" must be installed in schema "pgsodium"',
                 'cannot install pgsodium in any other schema');
SELECT * FROM finish();
ROLLBACK;

CREATE EXTENSION pgsodium;

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
\ir keys.sql
