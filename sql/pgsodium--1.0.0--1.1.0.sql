CREATE FUNCTION crypto_kdf_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_kdf_derive_from_key(subkey_size bigint, subkey_id bigint, context bytea, master_key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_derive_from_key'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE crypto_kx_keypair AS (public bytea, secret bytea);

CREATE FUNCTION crypto_kx_new_keypair()
RETURNS crypto_kx_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_keypair'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_kx_new_seed()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_new_seed'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_kx_seed_new_keypair(seed bytea)
RETURNS crypto_kx_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_seed_keypair'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE crypto_kx_session AS (rx bytea, tx bytea);

CREATE FUNCTION crypto_kx_client_session_keys(client_pk bytea, client_sk bytea, server_pk bytea)
RETURNS crypto_kx_session
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_client_session_keys'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_kx_server_session_keys(server_pk bytea, server_sk bytea, client_pk bytea)
RETURNS crypto_kx_session
AS '$libdir/pgsodium', 'pgsodium_crypto_kx_server_session_keys'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_auth_hmacsha512_keygen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_keygen'
LANGUAGE C VOLATILE;

CREATE FUNCTION crypto_auth_hmacsha512(message bytea, secret bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_auth_hmacsha512_verify(hash bytea, message bytea, secret bytea)
RETURNS bool
AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_verify'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION randombytes_new_seed()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_randombytes_new_seed'
LANGUAGE C VOLATILE;

CREATE FUNCTION randombytes_buf_deterministic(size integer, seed bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_randombytes_buf_deterministic'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_sign_init()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_init'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_sign_update(state bytea, message bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_update'
LANGUAGE C IMMUTABLE;

CREATE FUNCTION crypto_sign_final_create(state bytea, key bytea)
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_final_create'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_sign_final_verify(state bytea, signature bytea, key bytea)
RETURNS boolean
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_final_verify'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION crypto_sign_update_agg1(state bytea, message bytea)
 RETURNS bytea
AS
$$
 SELECT crypto_sign_update(COALESCE(state, crypto_sign_init()), message);
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION crypto_sign_update_agg1(bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea). This
initializes state if it has not already been initialized.';

CREATE FUNCTION crypto_sign_update_agg2(cur_state bytea,
                 initial_state bytea,
				 message bytea)
 RETURNS bytea
as
$$
 SELECT crypto_sign_update(
       COALESCE(cur_state, initial_state),
	   message)
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION crypto_sign_update_agg2(bytea, bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea, bytea). This
initializes state to the state passed to the aggregate as a parameter,
if it has not already been initialized.';

CREATE AGGREGATE crypto_sign_update_agg(message bytea)
 (
  SFUNC = crypto_sign_update_agg1,
  STYPE = bytea,
  PARALLEL = unsafe);

COMMENT ON AGGREGATE crypto_sign_update_agg(bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';

CREATE AGGREGATE crypto_sign_update_agg(state bytea, message bytea)
 (
  SFUNC = crypto_sign_update_agg2,
  STYPE = bytea,
  PARALLEL = unsafe);

COMMENT ON AGGREGATE crypto_sign_update_agg(bytea, bytea) IS
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

DROP FUNCTION crypto_box_new_keypair();

CREATE FUNCTION crypto_box_new_keypair()
RETURNS crypto_box_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_box_keypair'
LANGUAGE C VOLATILE;

DROP FUNCTION crypto_sign_new_keypair();

CREATE FUNCTION crypto_sign_new_keypair()
RETURNS crypto_sign_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_keypair'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_box_new_seed()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_box_new_seed'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_box_seed_new_keypair(seed bytea)
RETURNS crypto_box_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_box_seed_keypair'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION crypto_sign_new_seed()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_new_seed'
LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION crypto_sign_seed_new_keypair(seed bytea)
RETURNS crypto_sign_keypair
AS '$libdir/pgsodium', 'pgsodium_crypto_sign_seed_keypair'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pgsodium_derive(key_id bigint, key_len integer = 32, context bytea = decode('pgsodium', 'escape'))
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_derive'
LANGUAGE C VOLATILE;
