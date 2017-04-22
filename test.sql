\set ECHO none
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager

\set ON_ERROR_ROLLBACK 1
\set ON_ERROR_STOP true
\set QUIET 1

DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium;

BEGIN;
SELECT plan(12);

SELECT lives_ok($$SELECT pgsodium_randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT pgsodium_randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT pgsodium_randombytes_buf(10)$$, 'randombytes_buf');

select pgsodium_crypto_secretbox_keygen() boxkey \gset
\set quoted_boxkey '\'' :boxkey '\''

select pgsodium_crypto_secretbox_noncegen() secretboxnonce \gset
\set quoted_secretboxnonce '\'' :secretboxnonce '\''

select pgsodium_crypto_secretbox('bob is your uncle', :quoted_boxkey, :quoted_secretboxnonce) secretbox \gset
\set quoted_secretbox '\'' :secretbox '\''

SELECT is(pgsodium_crypto_secretbox_open(:quoted_secretbox, :quoted_boxkey, :quoted_secretboxnonce),
          'bob is your uncle', 'secretbox_open');

SELECT pgsodium_crypto_auth_keygen() authkey \gset
\set quoted_authkey '\'' :authkey '\''

SELECT pgsodium_crypto_auth('bob is your uncle', :quoted_authkey) auth_mac \gset
\set quoted_auth_mac '\'' :auth_mac '\''

SELECT ok(pgsodium_crypto_auth_verify(:quoted_auth_mac, 'bob is your uncle', :quoted_authkey),
          'crypto_auth_verify');
SELECT ok(not pgsodium_crypto_auth_verify('bad mac', 'bob is your uncle', :quoted_authkey),
          'crypto_auth_verify bad mac');
SELECT ok(not pgsodium_crypto_auth_verify(:quoted_auth_mac, 'bob is your uncle', 'bad key'),
          'crypto_auth_verify bad key');

SELECT is(pgsodium_crypto_generichash('bob is your uncle'),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash');

SELECT is(pgsodium_crypto_generichash('bob is your uncle', NULL),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash NULL key');

SELECT is(pgsodium_crypto_generichash('bob is your uncle', 'super sekret key'),
          '\xe8e9e180d918ea9afe0bf44d1945ec356b2b6845e9a4c31acc6c02d826036e41',
          'crypto_generichash with key');

SELECT is(pgsodium_crypto_shorthash('bob is your uncle', 'super sekret key'),
          '\xe080614efb824a15',
          'crypto_shorthash');

SELECT pgsodium_crypto_box_noncegen() boxnonce \gset
\set quoted_boxnonce '\'' :boxnonce '\''

SELECT public, secret FROM pgsodium_crypto_box_keypair() \gset bob_
\set quoted_bob_public '\'' :bob_public '\''
\set quoted_bob_secret '\'' :bob_secret '\''

SELECT public, secret FROM pgsodium_crypto_box_keypair() \gset alice_
\set quoted_alice_public '\'' :alice_public '\''
\set quoted_alice_secret '\'' :alice_secret '\''
    
select pgsodium_crypto_box('bob is your uncle', :quoted_boxnonce, :quoted_bob_public, :quoted_alice_secret) secretbox \gset
\set quoted_secretbox '\'' :secretbox '\''

SELECT is(pgsodium_crypto_box_open(:quoted_secretbox, :quoted_boxnonce, :quoted_alice_public, :quoted_bob_secret),
          'bob is your uncle', 'box_open');

SELECT * FROM finish();
ROLLBACK;
