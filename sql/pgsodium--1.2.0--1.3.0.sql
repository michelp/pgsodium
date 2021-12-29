
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

CREATE FUNCTION crypto_stream_xchacha20(bigint, bytea, bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bigint, context bytea = 'pgosdium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_by_id'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bigint, context bytea = 'pgsodium')
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_ic_by_id'
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

-- aead_det

CREATE FUNCTION crypto_aead_det_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_aead_det_encrypt(message bytea, additional bytea, key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_encrypt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_aead_det_decrypt(ciphertext bytea, additional bytea, key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_decrypt'
LANGUAGE C IMMUTABLE STRICT;

-- CREATE FUNCTION crypto_aead_det_encrypt(message bytea, additional bytea, key_id bigint, context bytea = 'pgsodium')
-- RETURNS bytea
-- AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_encrypt_by_id'
-- LANGUAGE C IMMUTABLE STRICT;

-- CREATE FUNCTION crypto_aead_det_decrypt(message bytea, additional bytea, key_id bigint, context bytea = 'pgsodium')
-- RETURNS bytea
-- AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_decrypt_by_id'
-- LANGUAGE C IMMUTABLE STRICT;



-- Sign-Cryption

CREATE TYPE crypto_signcrypt_state_sig AS (state bytea, shared_key bytea);
CREATE TYPE crypto_signcrypt_keypair AS (public bytea, secret bytea);

CREATE FUNCTION crypto_signcrypt_new_kepair()
RETURNS crypto_signcrypt_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_keypair'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_signcrypt_sign_before(sender bytea, recipient bytea, sender_sk bytea, recipient_pk bytea, additional bytea)
RETURNS crypto_signcrypt_state_sig
AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_sign_before'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_signcrypt_sign_after(state bytea, sender_sk bytea, ciphertext bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_sign_after'
LANGUAGE C IMMUTABLE STRICT;
