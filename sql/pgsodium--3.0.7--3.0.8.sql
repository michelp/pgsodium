CREATE OR REPLACE FUNCTION pgsodium.crypto_sign_update_agg1(state bytea, message bytea)
 RETURNS bytea
AS
$$
 SELECT pgsodium.crypto_sign_update(COALESCE(state, pgsodium.crypto_sign_init()), message);
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg1(bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea). This
initializes state if it has not already been initialized.';

CREATE OR REPLACE FUNCTION pgsodium.crypto_sign_update_agg2(cur_state bytea,
                 initial_state bytea,
				 message bytea)
 RETURNS bytea
as
$$
 SELECT pgsodium.crypto_sign_update(
       COALESCE(cur_state, initial_state),
	   message)
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg2(bytea, bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea, bytea). This
initializes state to the state passed to the aggregate as a parameter,
if it has not already been initialized.';

CREATE OR REPLACE AGGREGATE pgsodium.crypto_sign_update_agg(message bytea)
 (
  SFUNC = pgsodium.crypto_sign_update_agg1,
  STYPE = bytea,
  PARALLEL = unsafe);

COMMENT ON AGGREGATE pgsodium.crypto_sign_update_agg(bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';

CREATE OR REPLACE AGGREGATE pgsodium.crypto_sign_update_agg(state bytea, message bytea)
 (
  SFUNC = pgsodium.crypto_sign_update_agg2,
  STYPE = bytea,
  PARALLEL = unsafe);

COMMENT ON AGGREGATE pgsodium.crypto_sign_update_agg(bytea, bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

The first argument to this aggregate is the input state. This may be
the result of a previous crypto_sign_update_agg(), a previous
crypto_sign_update().

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';


CREATE OR REPLACE VIEW pgsodium.valid_key AS
  SELECT id, name, status, key_type, key_id, key_context, created, expires, associated_data
    FROM pgsodium.key
   WHERE  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires > now() END;

ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_box_seed_new_keypair(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_open(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_seal(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_seal_open(bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_generichash(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_generichash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_generichash(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_shorthash(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_shorthash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_shorthash(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.sodium_bin2base64(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.sodium_base642bin(text) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_kdf_derive_from_key(bigint, bigint, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash_str(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash_str_verify(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_uniform(integer) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_buf(integer) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_buf_deterministic(integer, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_secretbox(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_secretbox_open(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox_open(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox_open(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_hash_sha256(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_hash_sha512(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_seed_new_keypair(bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_sign(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_detached(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_final_create(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_final_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_open(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_seed_new_keypair(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_verify_detached(bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_signcrypt_sign_after(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_sign_before(bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_after(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_before(bytea, bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_public(bytea, bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_stream_xchacha20(bigint, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20(bigint, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bigint, bytea) CALLED ON NULL INPUT;
