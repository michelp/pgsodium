
-- secretstream

CREATE FUNCTION crypto_secretstream_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_secretstream_xchacha20poly1305_keygen'
LANGUAGE C VOLATILE;

-- stream

CREATE FUNCTION crypto_stream_xchacha20_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_stream_xchacha20_noncegen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_noncegen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_stream_xchacha20(bigint, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_ic'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_cmp(text, text)
RETURNS bool
AS '$libdir/pgsodium', 'pgsodium_cmp'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_generichash(message bytea, key bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_generichash_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_shorthash(message bytea, key bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_shorthash_by_id'
LANGUAGE C IMMUTABLE STRICT;

-- hmac

CREATE FUNCTION crypto_auth_hmacsha512(message bytea, key_id bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_auth_hmacsha512_verify(hash bytea, message bytea, key_id bigint, context bytea = 'pgsodium')
RETURNS bool
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_verify_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_auth_hmacsha256(message bytea, key_id bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_auth_hmacsha256_verify(hash bytea, message bytea, key_id bigint, context bytea = 'pgsodium')
RETURNS bool
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_verify_by_id'
LANGUAGE C IMMUTABLE STRICT;
