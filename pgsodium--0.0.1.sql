-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgsodium" to load this file. \quit

CREATE FUNCTION pgsodium_randombytes_random()
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_randombytes_uniform(integer)
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsodium_randombytes_buf(integer)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsodium_crypto_secretbox_keygen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_secretbox_noncegen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_secretbox(text, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_secretbox_open(bytea, bytea, bytea)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth(text, bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth_verify(bytea, text, bytea)
RETURNS boolean
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth_keygen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_generichash(text, bytea DEFAULT NULL)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_shorthash(text, bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE STRICT;

CREATE TYPE pgsodium_crypto_box_keypair AS (public bytea, secret bytea);

CREATE OR REPLACE FUNCTION pgsodium_crypto_box_keypair()
RETURNS SETOF pgsodium_crypto_box_keypair
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_box_noncegen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_box(text, bytea, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_box_open(bytea, bytea, bytea, bytea)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;
