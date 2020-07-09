CREATE FUNCTION crypto_auth_hmacsha256_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_auth_hmacsha256(message bytea, secret bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_auth_hmacsha256_verify(hash bytea, message bytea, secret bytea)
RETURNS bool
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_verify'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_hash_sha256(message bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_hash_sha256'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_hash_sha512(message bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_hash_sha512'
LANGUAGE C IMMUTABLE STRICT;

DROP FUNCTION crypto_kdf_derive_from_key(subkey_size bigint, subkey_id bigint, context bytea, master_key bytea);

CREATE FUNCTION crypto_kdf_derive_from_key(subkey_size bigint, subkey_id bigint, context bytea, primary_key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_derive_from_key'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION derive_key(key_id bigint, key_len integer = 32, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_derive'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_shorthash_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_shorthash_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_generichash_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_generichash_keygen'
LANGUAGE C VOLATILE;

