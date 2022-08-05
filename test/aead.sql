BEGIN;
SELECT plan(7);

SELECT crypto_aead_ietf_keygen() aeadkey \gset
SELECT crypto_aead_ietf_noncegen() aeadnonce \gset

SELECT crypto_aead_ietf_encrypt(
    'bob is your uncle', 'and also your friend', :'aeadnonce', :'aeadkey'::bytea) aead \gset

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt(%L, 'and also your friend', 'bad nonce', %L::bytea)$$, :'aead', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_encrypt: invalid nonce', 'crypto_aead_ietf_encrypt invalid nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt(%L, 'and also your friend', %L, 'bad_key'::bytea)$$, :'aead', :'aeadnonce'),
                 '22000', 'pgsodium_crypto_aead_ietf_encrypt: invalid key', 'crypto_aead_ietf_encrypt invalid key');

SELECT is(crypto_aead_ietf_decrypt(:'aead', 'and also your friend', :'aeadnonce', :'aeadkey'::bytea),
          'bob is your uncle', 'crypto_aead_ietf_decrypt');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(%L, 'and also your friend', 'bad nonce', %L::bytea)$$, :'aead', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid nonce', 'crypto_aead_ietf_decrypt invalid nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(%L, 'and also your friend', %L, 'bad_key'::bytea)$$, :'aead', :'aeadnonce'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid key', 'crypto_aead_ietf_decrypt invalid key');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt('foo', 'and also your friend', %L, %L::bytea)$$, :'aeadnonce', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid message', 'crypto_aead_ietf_decrypt invalid message');

SELECT crypto_aead_det_keygen() detkey \gset

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', 'and also your friend', :'detkey'::bytea) detaead \gset

SELECT is(crypto_aead_det_decrypt(:'detaead', 'and also your friend', :'detkey'::bytea),
          'bob is your uncle', 'crypto_aead_det_decrypt');

SELECT * FROM finish();
ROLLBACK;

\if :serverkeys
BEGIN;
SELECT plan(10);
SET ROLE pgsodium_keyiduser;

SELECT crypto_aead_ietf_encrypt(
    'bob is your uncle', 'and also your friend', :'aeadnonce', 1) aead \gset

SELECT is(crypto_aead_ietf_decrypt(:'aead', 'and also your friend', :'aeadnonce', 1),
          'bob is your uncle', 'crypto_aead_ietf_decrypt by id');

SELECT throws_ok($$select crypto_aead_ietf_encrypt('bob is your uncle', 'and also your friend', 'whatever', 'whatever'::bytea)$$,
                 '42501', 'permission denied for function crypto_aead_ietf_encrypt', 'crypto_aead_ietf_encrypt denied');
SELECT throws_ok($$select crypto_aead_ietf_decrypt('bob is your uncle', 'and also your friend', 'whatever', 'whatever'::bytea)$$,
                 '42501', 'permission denied for function crypto_aead_ietf_decrypt', 'crypto_aead_ietf_decrypt denied');

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', 'and also your friend', 32) detaeadid \gset

SELECT is(crypto_aead_det_decrypt(:'detaeadid', 'and also your friend', 32),
          'bob is your uncle', 'crypto_aead_det_decrypt by id');

-- Test UUID key ids into key table

RESET ROLE;

SET ROLE pgsodium_keymaker;
select id as det_key_uuid from create_key('det Test Key') \gset
select id as ietf_key_uuid from create_key('ietf Test Key', key_type:='aead-ietf') \gset
RESET ROLE;

SET ROLE pgsodium_keyiduser;

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', 'and also your friend', :'det_key_uuid'::uuid) detaeadid \gset

SELECT is(crypto_aead_det_decrypt(:'detaeadid', 'and also your friend', :'det_key_uuid'::uuid),
          'bob is your uncle', 'crypto_aead_ietf_decrypt by uuid');

SELECT throws_ok($$select crypto_aead_det_encrypt('bob is your uncle', 'and also your friend', uuid_nil())$$,
                 'P0002', 'query returned no rows', 'crypto_aead_det_encrypt invalid uuid');
SELECT throws_ok($$select crypto_aead_det_decrypt('bob is your uncle', 'and also your friend', uuid_nil())$$,
                 'P0002', 'query returned no rows', 'crypto_aead_det_decrypt invalid uuid');

SELECT crypto_aead_ietf_encrypt(
    'bob is your uncle', 'and also your friend', :'aeadnonce', :'ietf_key_uuid'::uuid) detaeadid \gset

SELECT is(crypto_aead_ietf_decrypt(:'detaeadid', 'and also your friend', :'aeadnonce', :'ietf_key_uuid'::uuid),
          'bob is your uncle', 'crypto_aead_ietf_decrypt by uuid');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt('bob is your uncle', 'and also your friend', %L, uuid_nil())$$, :'aeadnonce'),
                 'P0002', 'query returned no rows', 'crypto_aead_ietf_encrypt invalid uuid');
SELECT throws_ok(format($$select crypto_aead_ietf_decrypt('bob is your uncle', 'and also your friend', %L, uuid_nil())$$, :'aeadnonce'),
                 'P0002', 'query returned no rows', 'crypto_aead_ietf_decrypt invalid uuid');

RESET ROLE;
SELECT * FROM finish();
ROLLBACK;
\endif
