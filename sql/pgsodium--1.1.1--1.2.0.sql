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


