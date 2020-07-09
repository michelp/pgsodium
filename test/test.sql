\set ECHO none
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager

\set ON_ERROR_ROLLBACK 1
\set ON_ERROR_STOP true
\set QUIET 1


CREATE EXTENSION IF NOT EXISTS pgtap;
CREATE EXTENSION IF NOT EXISTS pgsodium;

BEGIN;
SELECT plan(58);

-- random

SELECT lives_ok($$SELECT randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT randombytes_buf(10)$$, 'randombytes_buf');
SELECT randombytes_new_seed() bufseed \gset
SELECT lives_ok(format($$SELECT randombytes_buf_deterministic(10, %L)$$, :'bufseed'),
        'randombytes_buf_deterministic');

-- secret key crypto

SELECT crypto_secretbox_keygen() boxkey \gset
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'boxkey') secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'boxkey'),
          'bob is your uncle', 'secretbox_open');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, 'bad nonce', %L)$$, :'secretbox', :'boxkey'),
	   	         '22000', 'invalid nonce', 'crypto_secretbox_open invalid nonce');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, %L, 'bad_key')$$, :'secretbox', :'secretboxnonce'),
	   	         '22000', 'invalid key', 'crypto_secretbox_open invalid key');

SELECT throws_ok(format($$select crypto_secretbox_open('foo', %L, %L)$$, :'secretboxnonce', :'boxkey'),
	   	         '22000', 'invalid message', 'crypto_secretbox_open invalid message');

-- secret key auth

SELECT crypto_auth_keygen() authkey \gset

SELECT crypto_auth('bob is your uncle', :'authkey') auth_mac \gset

SELECT throws_ok($$select crypto_auth('bob is your uncle', 'bad_key')$$,
	             '22000', 'invalid key', 'crypto_auth invalid key');

SELECT ok(crypto_auth_verify(:'auth_mac', 'bob is your uncle', :'authkey'),
          'crypto_auth_verify');
SELECT throws_ok(format($$select crypto_auth_verify('bad mac', 'bob is your uncle', %L)$$, :'authkey'),
	             '22000', 'invalid mac', 'crypto_auth_verify invalid mac');
SELECT throws_ok(format($$select crypto_auth_verify(%L, 'bob is your uncle', 'bad_key')$$, :'auth_mac'),
	             '22000', 'invalid key', 'crypto_auth_verify invalid key');

-- hashing

SELECT crypto_generichash_keygen() generickey \gset

SELECT is(crypto_generichash('bob is your uncle'),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash');

SELECT is(crypto_generichash('bob is your uncle', NULL),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash NULL key');

SELECT lives_ok(format($$select crypto_generichash('bob is your uncle', %L)$$, :'generickey'),
          'crypto_generichash with key');

SELECT crypto_shorthash_keygen() shortkey \gset

SELECT lives_ok(format($$select crypto_shorthash('bob is your uncle', %L)$$, :'shortkey'), 'crypto_shorthash');

SELECT throws_ok($$select crypto_shorthash('bob is your uncle', 's')$$,
	   '22000', 'invalid key', 'crypto_shorthash invalid key');

-- public key crypto (box)

SELECT crypto_box_noncegen() boxnonce \gset
SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

SELECT is(crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_open');

SELECT throws_ok(format($$select crypto_box_open(%L, 'bad nonce', %L, %L)$$, :'box', :'alice_public', :'bob_secret'),
	   	         '22000', 'invalid nonce', 'crypto_box_open invalid nonce');

SELECT throws_ok(format($$select crypto_box_open(%L, %L, 'bad_key', %L)$$, :'box', :'boxnonce', :'bob_secret'),
	   	         '22000', 'invalid public key', 'crypto_box_open invalid public key');

SELECT throws_ok(format($$select crypto_box_open(%L, %L, %L, 'bad_key')$$, :'box', :'boxnonce', :'alice_public'),
	   	         '22000', 'invalid secret key', 'crypto_box_open invalid secret key');

SELECT throws_ok(format($$select crypto_box_open('foo', %L, %L, %L)$$, :'boxnonce', :'alice_public', :'bob_secret'),
	   	         '22000', 'invalid message', 'crypto_box_open invalid message');

SELECT crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset

SELECT is(crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_seal/open');

SELECT throws_ok(format($$select crypto_box_seal_open(%L, 'bad_key', %L)$$, :'sealed', :'bob_secret'),
	   	         '22000', 'invalid public key', 'crypto_secretbox_seal_open public key');

SELECT throws_ok(format($$select crypto_box_seal_open(%L, %L, 'bad_key')$$, :'sealed', :'bob_public'),
	   	         '22000', 'invalid secret key', 'crypto_secretbox_seal_open secret key');

SELECT throws_ok(format($$select crypto_box_seal_open('foo', %L, %L)$$, :'bob_public', :'bob_secret'),
	   	         '22000', 'invalid message', 'crypto_secretbox_seal_open invalid message');

SELECT lives_ok($$select crypto_sign_seed_new_keypair(crypto_sign_new_seed())$$, 'crypto_sign_seed_new_keypair');
SELECT throws_ok($$select crypto_sign_seed_new_keypair('bogus')$$, '22000', 'invalid seed', 'crypto_sign_seed_new_keypair invalid seed');

SELECT public, secret FROM crypto_sign_new_keypair() \gset sign_

SELECT crypto_sign('bob is your uncle', :'sign_secret') signed \gset
SELECT throws_ok($$select crypto_sign('bob is your uncle', 's')$$,
	   '22000', 'invalid secret key', 'crypto_sign invalid key');

SELECT is(crypto_sign_open(:'signed', :'sign_public'),
          'bob is your uncle', 'crypto_sign_open');

SELECT throws_ok(format($$select crypto_sign_open(%L, 'bad_key')$$, :'signed'),
	   	         '22000', 'invalid public key', 'crypto_sign_open invalid public key');

SELECT throws_ok(format($$select crypto_sign_open('foo', %L)$$, :'sign_public'),
	   	         '22000', 'invalid message', 'crypto_sign_open invalid message');

-- public key signatures
-- We will sign our previously generated sealed box

SELECT throws_ok($$select crypto_sign_detached('foo', 'bar')$$,
	   	         '22000', 'invalid secret key', 'crypto_sign_detached invalid secret key');

SELECT throws_ok($$select crypto_sign_verify_detached('foo', 'bar', 'bork')$$,
	   	         '22000', 'invalid public key', 'crypto_sign_verify_detached invalid public key');

SELECT crypto_sign_detached(:'sealed', :'sign_secret') detached \gset

SELECT is(crypto_sign_verify_detached(:'detached', :'sealed', :'sign_public'),
          true, 'crypto_sign_detached/verify');

SELECT is(crypto_sign_verify_detached(:'detached', 'xyzzy', :'sign_public'),
          false, 'crypto_sign_detached/verify (incorrect message)');

-- Check Multi-part messages
WITH parts(msg) AS
  (
    VALUES ('Hello Alice'),
    	   ('Hello Bob'),
    	   ('Hello Carol')
  ),
tampered(msg) AS
  (
    VALUES ('Hello Alice'),
    	   ('Hello Bob'),
    	   ('Hello CaRol')
  ),
prep1 AS
  (
    -- First form of aggregate
    SELECT crypto_sign_update_agg(p.msg::bytea) state
      FROM parts p
  ),
prep2 AS
  (
    -- Second form of aggregate
    SELECT crypto_sign_update_agg(crypto_sign_init(), p.msg::bytea) state
      FROM parts p
  ),
prepv AS
  (
    -- Second form of aggregate from tampered parts
    SELECT crypto_sign_update_agg(crypto_sign_init(), t.msg::bytea) state
      FROM tampered t
  ),
sig AS
  (
    SELECT crypto_sign_final_create(p.state, :'sign_secret') as sig
      FROM prep1 p
  ),
verify AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prep1 p
     CROSS JOIN sig s
  ),
verify2 AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prep2 p
     CROSS JOIN sig s
  ),
noverify AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prepv p
     CROSS JOIN sig s
  )
SELECT ok(verify, 'Multi-part signature')
  FROM verify
UNION ALL
SELECT ok(verify, 'Multi-part signature(2)')
  FROM verify2
UNION ALL
-- Each time we generate state it will be different, even though sig
-- can be verified.
SELECT isnt(p1.state, p2.state, 'Multi-part states differ')
  FROM prep1 p1 CROSS JOIN prep2 p2
UNION ALL
SELECT ok(not verify, 'Multi-part signature detects tampering')
  FROM noverify;

-- pwhash

SELECT lives_ok($$SELECT crypto_pwhash_saltgen()$$, 'crypto_pwhash_saltgen');

SELECT is(crypto_pwhash('Correct Horse Battery Staple', '\xccfe2b51d426f88f6f8f18c24635616b'),
        '\x77d029a9b3035c88f186ed0f69f58386ad0bd5252851b4e89f0d7057b5081342',
        'crypto_pwhash');

SELECT ok(crypto_pwhash_str_verify(crypto_pwhash_str('Correct Horse Battery Staple'),
          'Correct Horse Battery Staple'),
          'crypto_pwhash_str_verify');

-- this pattern below is an example of how to turn off query logging
-- of secrets via session variables.

SET LOCAL log_statement = 'none';
SET LOCAL app.bob_secret = :'bob_secret';
SET LOCAL app.alice_secret = :'alice_secret';
RESET log_statement;

-- crypto box

SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public',
                  current_setting('app.alice_secret')::bytea) box \gset

SELECT is(crypto_box_open(:'box', :'boxnonce', :'alice_public',
                          current_setting('app.bob_secret')::bytea),
                          'bob is your uncle', 'crypto_box_open');

-- Key Derivation

SELECT crypto_kdf_keygen() kdfkey \gset
SELECT length(crypto_kdf_derive_from_key(64, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 64, 'kdf byte derived subkey');

SELECT length(crypto_kdf_derive_from_key(32, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 32, 'kdf 32 byte derived subkey');

SELECT is(crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'),
    crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'), 'kdf subkeys are deterministic.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(32, 2, '__aut__', %L)$$, :'kdfkey'),
    '22000', 'crypto_kdf_derive_from_key: context must be 8 bytes',
    'kdf context must be 8 bytes.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(15, 2, '__auth__', %L)$$, :'kdfkey'),
    '22000', 'crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be >= 16');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(65, 2, '__auth__', %L)$$, :'kdfkey'),
    '22000', 'crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be <= 64');

-- Key Exchange

SELECT public, secret FROM crypto_kx_new_keypair() \gset bob_
SELECT public, secret FROM crypto_kx_new_keypair() \gset alice_

SELECT crypto_kx_new_seed() kxseed \gset

SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_bob_
SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_alice_

SELECT tx, rx FROM crypto_kx_client_session_keys(
    :'seed_bob_public', :'seed_bob_secret',
    :'seed_alice_public') \gset session_bob_

SELECT tx, rx FROM crypto_kx_server_session_keys(
    :'seed_alice_public', :'seed_alice_secret',
    :'seed_bob_public') \gset session_alice_

SELECT crypto_secretbox('hello alice', :'secretboxnonce', :'session_bob_tx') bob_to_alice \gset

SELECT is(crypto_secretbox_open(:'bob_to_alice', :'secretboxnonce', :'session_alice_rx'),
          'hello alice', 'secretbox_open session key');

SELECT crypto_secretbox('hello bob', :'secretboxnonce', :'session_alice_tx') alice_to_bob \gset

SELECT is(crypto_secretbox_open(:'alice_to_bob', :'secretboxnonce', :'session_bob_rx'),
          'hello bob', 'secretbox_open session key');

-- sha2

select is(crypto_hash_sha256('bob is your uncle'),
    '\x5eff82dc2ca0cfbc0d0eaa95b13b7fbec11540e217b0fe2a6f3c7d12f657630d', 'sha256');
select is(crypto_hash_sha512('bob is your uncle'),
    '\xd8adbd01462f1aad1b91a4557d5c865b63dab1b9181cb02f2123f50d210b74a53754a18b09d9f75e38101ce6de04879b35eca91992fade0bb6842f4ea556e952',
    'sha512');

-- hmac

select crypto_auth_hmacsha512_keygen() hmac512key \gset
select crypto_auth_hmacsha512('food', :'hmac512key') hmac512 \gset

select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'hmac512key'), true, 'hmac512 verified');
select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'hmac512key'), false, 'hmac512 not verified');

select crypto_auth_hmacsha256_keygen() hmac256key \gset
select crypto_auth_hmacsha256('food', :'hmac256key') hmac256 \gset

select is(crypto_auth_hmacsha256_verify(:'hmac256', 'food', :'hmac256key'), true, 'hmac256 verified');
select is(crypto_auth_hmacsha256_verify(:'hmac256', 'fo0d', :'hmac256key'), false, 'hmac256 not verified');

SELECT * FROM finish();
ROLLBACK;

select exists (select * from pg_settings where name = 'shared_preload_libraries' and setting ilike '%pgsodium%') serverkeys \gset
\if :serverkeys
BEGIN;

-- Server Derived Keys

SELECT plan(4);

select is(derive_key(1), derive_key(1), 'derived key are equal by id');
select isnt(derive_key(1), derive_key(2), 'disequal derived key');
select is(length(derive_key(2, 64)), 64, 'key len is 64 bytes');
select isnt(derive_key(2, 32, 'foozball'), derive_key(2, 32), 'disequal context');
SELECT * FROM finish();
ROLLBACK;
\endif

-- test relocatable schema

BEGIN;
SELECT plan(3);

CREATE SCHEMA pgsodium;
DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

SELECT lives_ok($$SELECT pgsodium.randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT pgsodium.randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT pgsodium.randombytes_buf(10)$$, 'randombytes_buf');

SELECT * FROM finish();
ROLLBACK;
