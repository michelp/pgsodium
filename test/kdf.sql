BEGIN;
SELECT plan(6);

SELECT crypto_kdf_keygen() kdfkey \gset
SELECT length(crypto_kdf_derive_from_key(64, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 64, 'kdf byte derived subkey');

SELECT length(crypto_kdf_derive_from_key(32, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 32, 'kdf 32 byte derived subkey');

SELECT is(crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'),
    crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'), 'kdf subkeys are deterministic.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(32, 2, '__aut__', %L)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: context must be 8 bytes',
    'kdf context must be 8 bytes.');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(15, 2, '__auth__', %L)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be >= 16');

SELECT throws_ok(format($$SELECT crypto_kdf_derive_from_key(65, 2, '__auth__', %L)$$, :'kdfkey'),
    '22000', 'pgsodium_crypto_kdf_derive_from_key: invalid key size requested',
    'kdf keysize must be <= 64');

SELECT * FROM finish();
ROLLBACK;
