BEGIN;
SELECT plan(4);


SELECT crypto_auth_keygen() authkey \gset

SELECT crypto_auth('bob is your uncle', :'authkey'::bytea) auth_mac \gset

SELECT throws_ok($$select crypto_auth('bob is your uncle', 'bad_key'::bytea)$$,
                 '22000', 'pgsodium_crypto_auth: invalid key', 'crypto_auth invalid key');

SELECT ok(crypto_auth_verify(:'auth_mac', 'bob is your uncle', :'authkey'::bytea),
          'crypto_auth_verify');
SELECT throws_ok(format($$select crypto_auth_verify('bad mac', 'bob is your uncle', %L::bytea)$$, :'authkey'),
                 '22000', 'pgsodium_crypto_auth_verify: invalid mac', 'crypto_auth_verify invalid mac');
SELECT throws_ok(format($$select crypto_auth_verify(%L, 'bob is your uncle', 'bad_key'::bytea)$$, :'auth_mac'),
                 '22000', 'pgsodium_crypto_auth_verify: invalid key', 'crypto_auth_verify invalid key');

SELECT * FROM finish();
ROLLBACK;

\if :serverkeys

BEGIN;
SELECT plan(2);

SELECT crypto_auth('bob is your uncle', 1) auth_mac_by_id \gset
SELECT ok(crypto_auth_verify(:'auth_mac_by_id', 'bob is your uncle', 1),
          'crypto_auth_verify by id');

SELECT id AS auth_key_id FROM create_key('auth') auth_key_id \gset

SELECT crypto_auth('bobo is your monkey', :'auth_key_id'::uuid) auth_mac_by_uuid \gset
SELECT ok(crypto_auth_verify(:'auth_mac_by_uuid', 'bobo is your monkey', :'auth_key_id'::uuid),
          'crypto_auth_verify by uuid');

SELECT * FROM finish();
ROLLBACK;
\endif
