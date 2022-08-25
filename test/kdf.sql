BEGIN;
SELECT plan(6);

SELECT crypto_kdf_keygen() kdfkey \gset
SELECT length(crypto_kdf_derive_from_key(64, 1, '__auth__', :'kdfkey'::bytea)) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 64, 'kdf byte derived subkey');

SELECT length(crypto_kdf_derive_from_key(32, 1, '__auth__', :'kdfkey'::bytea)) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 32, 'kdf 32 byte derived subkey');

SELECT is(crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'::bytea),
    crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'::bytea), 'kdf subkeys are deterministic.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(32, 2, '__aut__', %L::bytea)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: context must be 8 bytes',
    'kdf context must be 8 bytes.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(15, 2, '__auth__', %L::bytea)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be >= 16');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(65, 2, '__auth__', %L::bytea)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be <= 64');

SELECT * FROM finish();
ROLLBACK;

\if :serverkeys

BEGIN;
SELECT plan(1);
select id as kdf_key_id from create_key('kdf') \gset
SELECT lives_ok(format($$select crypto_kdf_derive_from_key(32, 42, 'pgsodium', %L::uuid)$$, :'kdf_key_id'),
          'crypto_kdf_derive_from_key by uuid');

SELECT * FROM finish();
ROLLBACK;
\endif
