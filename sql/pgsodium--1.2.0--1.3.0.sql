
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

CREATE FUNCTION crypto_stream_xchacha20(integer, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor'
LANGUAGE C VOLATILE;

