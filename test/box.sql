BEGIN;
SELECT plan(9);

SELECT crypto_box_noncegen() boxnonce \gset
SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

SELECT is(crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_open');

SELECT throws_ok(format($$select crypto_box_open(%L, 'bad nonce', %L, %L)$$, :'box', :'alice_public', :'bob_secret'),
                 '22000', 'pgsodium_crypto_box_open: invalid nonce', 'crypto_box_open invalid nonce');

SELECT throws_ok(format($$select crypto_box_open(%L, %L, 'bad_key', %L)$$, :'box', :'boxnonce', :'bob_secret'),
                 '22000', 'pgsodium_crypto_box_open: invalid public key', 'crypto_box_open invalid public key');

SELECT throws_ok(format($$select crypto_box_open(%L, %L, %L, 'bad_key')$$, :'box', :'boxnonce', :'alice_public'),
                 '22000', 'pgsodium_crypto_box_open: invalid secret key', 'crypto_box_open invalid secret key');

SELECT throws_ok(format($$select crypto_box_open('foo', %L, %L, %L)$$, :'boxnonce', :'alice_public', :'bob_secret'),
                 '22000', 'pgsodium_crypto_box_open: invalid message', 'crypto_box_open invalid message');

SELECT crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset

SELECT is(crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_seal/open');

SELECT throws_ok(format($$select crypto_box_seal_open(%L, 'bad_key', %L)$$, :'sealed', :'bob_secret'),
                 '22000', 'pgsodium_crypto_box_seal_open: invalid public key', 'crypto_box_seal_open public key');

SELECT throws_ok(format($$select crypto_box_seal_open(%L, %L, 'bad_key')$$, :'sealed', :'bob_public'),
                 '22000', 'pgsodium_crypto_box_seal_open: invalid secret key', 'crypto_box_seal_open secret key');

SELECT throws_ok(format($$select crypto_box_seal_open('foo', %L, %L)$$, :'bob_public', :'bob_secret'),
                 '22000', 'pgsodium_crypto_box_seal_open: invalid message', 'crypto_box_seal_open invalid message');

SELECT * FROM finish();
ROLLBACK;
