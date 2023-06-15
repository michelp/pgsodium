
SELECT crypto_aead_ietf_keygen() aeadkey \gset
SELECT crypto_aead_ietf_noncegen() aeadnonce \gset

SELECT crypto_aead_ietf_encrypt(
    'bob is your uncle', 'and also your friend', :'aeadnonce', :'aeadkey'::bytea) aead \gset

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt(%L, 'and also your friend', 'bad nonce', %L::bytea)$$, :'aead', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_encrypt: invalid nonce', 'crypto_aead_ietf_encrypt invalid nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt(%L, 'and also your friend', %L, 'bad_key'::bytea)$$, :'aead', :'aeadnonce'),
                 '22000', 'pgsodium_crypto_aead_ietf_encrypt: invalid key', 'crypto_aead_ietf_encrypt invalid key');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt(NULL, 'and also your friend',
    %L::bytea, %L::bytea)$$, :'aeadnonce', :'aeadkey'),
    '22000', 'pgsodium_crypto_aead_ietf_encrypt: message cannot be NULL', 'crypto_aead_ietf_encrypt null message');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt('bob is your uncle', 'and also your friend',
    NULL::bytea, %L::bytea)$$, :'aeadkey'),
    '22000', 'pgsodium_crypto_aead_ietf_encrypt: nonce cannot be NULL', 'crypto_aead_ietf_encrypt null nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt('bob is your uncle', 'and also your friend',
    %L::bytea, NULL::bytea)$$, :'aeadnonce'),
    '22000', 'pgsodium_crypto_aead_ietf_encrypt: key cannot be NULL', 'crypto_aead_ietf_encrypt null key');

SELECT is(crypto_aead_ietf_decrypt(:'aead', 'and also your friend', :'aeadnonce', :'aeadkey'::bytea),
          'bob is your uncle', 'crypto_aead_ietf_decrypt');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(%L, 'and also your friend', 'bad nonce', %L::bytea)$$, :'aead', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid nonce', 'crypto_aead_ietf_decrypt invalid nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(%L, 'and also your friend', %L, 'bad_key'::bytea)$$, :'aead', :'aeadnonce'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid key', 'crypto_aead_ietf_decrypt invalid key');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt('foo', 'and also your friend', %L, %L::bytea)$$, :'aeadnonce', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: invalid message', 'crypto_aead_ietf_decrypt invalid message');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(NULL::bytea, 'and also your friend', %L, %L::bytea)$$, :'aeadnonce', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: ciphertext cannot be NULL', 'crypto_aead_ietf_decrypt null message');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt(%L, 'and also your friend', NULL, 'bad_key'::bytea)$$, :'aead', :'aeadkey'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: nonce cannot be NULL', 'crypto_aead_ietf_decrypt null nonce');

SELECT throws_ok(format($$select crypto_aead_ietf_decrypt('foo', 'and also your friend', %L, NULL::bytea)$$, :'aeadnonce'),
                 '22000', 'pgsodium_crypto_aead_ietf_decrypt: key cannot be NULL', 'crypto_aead_ietf_decrypt null key');

SELECT crypto_aead_det_keygen() detkey \gset

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', 'and also your friend', :'detkey'::bytea) detaead \gset

SELECT is(crypto_aead_det_decrypt(:'detaead', 'and also your friend', :'detkey'::bytea),
          'bob is your uncle', 'crypto_aead_det_decrypt');

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', NULL, :'detkey'::bytea) detaead2 \gset

SELECT is(crypto_aead_det_decrypt(:'detaead2', NULL, :'detkey'::bytea),
          'bob is your uncle', 'crypto_aead_det_decrypt with NULL associated');

\if :serverkeys
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
select id as det_key_uuid from create_key('aead-det', 'det Test Key') \gset
select id as ietf_key_uuid from create_key('aead-ietf', 'ietf Test Key') \gset
RESET ROLE;

SET ROLE pgsodium_keyiduser;

SELECT crypto_aead_det_encrypt(
    'bob is your uncle', 'and also your friend', :'det_key_uuid'::uuid) detaeadid \gset

SELECT is(crypto_aead_det_decrypt(:'detaeadid', 'and also your friend', :'det_key_uuid'::uuid),
          'bob is your uncle', 'crypto_aead_ietf_decrypt by uuid');

select '00000000-0000-0000-0000-000000000000' as nil_uuid \gset

SELECT throws_ok($$select crypto_aead_det_encrypt('bob is your uncle', 'and also your friend', '00000000-0000-0000-0000-000000000000'::uuid)$$,
                 'P0002', 'query returned no rows', 'crypto_aead_det_encrypt invalid uuid');
SELECT throws_ok($$select crypto_aead_det_decrypt('bob is your uncle', 'and also your friend', '00000000-0000-0000-0000-000000000000'::uuid)$$,
                 'P0002', 'query returned no rows', 'crypto_aead_det_decrypt invalid uuid');

SELECT crypto_aead_ietf_encrypt(
    'bob is your uncle', 'and also your friend', :'aeadnonce', :'ietf_key_uuid'::uuid) detaeadid \gset

SELECT is(crypto_aead_ietf_decrypt(:'detaeadid', 'and also your friend', :'aeadnonce', :'ietf_key_uuid'::uuid),
          'bob is your uncle', 'crypto_aead_ietf_decrypt by uuid');

SELECT throws_ok(format($$select crypto_aead_ietf_encrypt('bob is your uncle', 'and also your friend', %L, '00000000-0000-0000-0000-000000000000'::uuid)$$, :'aeadnonce'),
                 'P0002', 'query returned no rows', 'crypto_aead_ietf_encrypt invalid uuid');
SELECT throws_ok(format($$select crypto_aead_ietf_decrypt('bob is your uncle', 'and also your friend', %L, '00000000-0000-0000-0000-000000000000'::uuid)$$, :'aeadnonce'),
                 'P0002', 'query returned no rows', 'crypto_aead_ietf_decrypt invalid uuid');

RESET ROLE;
\endif
