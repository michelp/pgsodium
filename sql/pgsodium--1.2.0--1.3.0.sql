CREATE FUNCTION crypto_secretstream_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_secretstream_xchacha20poly1305_keygen'
LANGUAGE C VOLATILE;

