-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgsodium" to load this file. \quit

CREATE FUNCTION pgsodium_randombytes_random()
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_randombytes_uniform(upper_bound integer)
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsodium_randombytes_buf(size integer)
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

CREATE FUNCTION pgsodium_crypto_secretbox(message text, nonce bytea, key bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_secretbox_open(ciphertext bytea, nonce bytea, key bytea)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth(message text, key bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth_verify(mac bytea, message text, key bytea)
RETURNS boolean
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_auth_keygen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_generichash(message text, key bytea DEFAULT NULL)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium_crypto_shorthash(message text, key bytea)
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

CREATE FUNCTION pgsodium_crypto_box(message text, nonce bytea, public bytea, secret bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_crypto_box_open(ciphertext bytea, nonce bytea, public bytea, secret bytea)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE pgsodium_crypto_sign_keypair AS (public bytea, secret bytea);

CREATE OR REPLACE FUNCTION pgsodium_crypto_sign_keypair()
RETURNS SETOF pgsodium_crypto_sign_keypair
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION pgsodium_crypto_sign(message text, key bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pgsodium_crypto_sign_open(signed_message bytea, key bytea)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pgsodium_crypto_pwhash_saltgen()
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION pgsodium_crypto_pwhash(password text, salt bytea)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pgsodium_crypto_pwhash_str(password text)
RETURNS text
AS '$libdir/pgsodium'
LANGUAGE C VOLATILE STRICT;

CREATE OR REPLACE FUNCTION pgsodium_crypto_pwhash_str_verify(hashed_password text, password text)
RETURNS bool
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;
