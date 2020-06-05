
CREATE FUNCTION crypto_kdf_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_kdf_derive_from_key(subkey_size bigint, subkey_id bigint, context bytea, master_key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_derive_from_key'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE crypto_kx_keypair AS (public bytea, secret bytea);

CREATE OR REPLACE FUNCTION crypto_kx_new_keypair()
RETURNS SETOF crypto_kx_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_keypair'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_kx_new_seed()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_new_seed'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_kx_seed_new_keypair(seed bytea)
RETURNS SETOF crypto_kx_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_seed_keypair'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE crypto_kx_session AS (rx bytea, tx bytea);

CREATE OR REPLACE FUNCTION crypto_kx_client_session_keys(client_pk bytea, client_sk bytea, server_pk bytea)
RETURNS SETOF crypto_kx_session
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_client_session_keys'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_kx_server_session_keys(server_pk bytea, server_sk bytea, client_pk bytea)
RETURNS SETOF crypto_kx_session
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_server_session_keys'
LANGUAGE C VOLATILE;
