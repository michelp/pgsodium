\set ECHO none
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager

\set ON_ERROR_ROLLBACK 1
\set ON_ERROR_STOP on
-- \set QUIET 1

\set extschema :extschema
SELECT CASE WHEN :'extschema' = ':extschema'
       THEN 'pgsodium'
       ELSE :'extschema'
       END AS extschema \gset

CREATE EXTENSION IF NOT EXISTS pgtap;
DROP ROLE IF EXISTS bobo;

CREATE SCHEMA IF NOT EXISTS :"extschema";
CREATE EXTENSION IF NOT EXISTS pgsodium SCHEMA :"extschema";

SET search_path = :'extschema', public;

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
