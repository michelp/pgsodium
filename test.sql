\set ECHO none
\set QUIET 1

\pset format unaligned
\pset tuples_only true
\pset pager

\set ON_ERROR_ROLLBACK 1
-- \set ON_ERROR_STOP true
\set QUIET 1

CREATE EXTENSION pgtap;
CREATE EXTENSION pgsodium;

BEGIN;
SELECT plan(20);

SELECT lives_ok($$SELECT randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT randombytes_buf(10)$$, 'randombytes_buf');

SELECT crypto_secretbox_keygen() boxkey \gset
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'boxkey') secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'boxkey'),
          'bob is your uncle', 'secretbox_open');

SELECT crypto_auth_keygen() authkey \gset

SELECT crypto_auth('bob is your uncle', :'authkey') auth_mac \gset

SELECT ok(crypto_auth_verify(:'auth_mac', 'bob is your uncle', :'authkey'),
          'crypto_auth_verify');
SELECT ok(not crypto_auth_verify('bad mac', 'bob is your uncle', :'authkey'),
          'crypto_auth_verify bad mac');
SELECT ok(not crypto_auth_verify(:'auth_mac', 'bob is your uncle', 'bad key'),
          'crypto_auth_verify bad key');

SELECT is(crypto_generichash('bob is your uncle'),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash');

SELECT is(crypto_generichash('bob is your uncle', NULL),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash NULL key');

SELECT is(crypto_generichash('bob is your uncle', 'super sekret key'),
          '\xe8e9e180d918ea9afe0bf44d1945ec356b2b6845e9a4c31acc6c02d826036e41',
          'crypto_generichash with key');

SELECT is(crypto_shorthash('bob is your uncle', 'super sekret key'),
          '\xe080614efb824a15',
          'crypto_shorthash');

SELECT crypto_box_noncegen() boxnonce \gset
SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

SELECT is(crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_open');

SELECT crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset

SELECT is(crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_seal/open');

SELECT public, secret FROM crypto_sign_new_keypair() \gset sign_

SELECT crypto_sign('bob is your uncle', :'sign_secret') signed \gset

SELECT is(crypto_sign_open(:'signed', :'sign_public'),
          'bob is your uncle', 'crypto_sign/open');

SELECT lives_ok($$SELECT crypto_pwhash_saltgen()$$, 'crypto_pwhash_saltgen');

SELECT is(crypto_pwhash('Correct Horse Battery Staple', '\xccfe2b51d426f88f6f8f18c24635616b'),
        '\x77d029a9b3035c88f186ed0f69f58386ad0bd5252851b4e89f0d7057b5081342',
        'crypto_pwhash');

SELECT ok(crypto_pwhash_str_verify(crypto_pwhash_str('Correct Horse Battery Staple'),
          'Correct Horse Battery Staple'),
          'crypto_pwhash_str_verify');

-- test relocatable schema

CREATE SCHEMA pgsodium;
DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

SELECT lives_ok($$SELECT pgsodium.randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT pgsodium.randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT pgsodium.randombytes_buf(10)$$, 'randombytes_buf');

SELECT * FROM finish();
ROLLBACK;
