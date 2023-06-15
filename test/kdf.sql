
SELECT crypto_kdf_keygen() kdfkey \gset
SELECT length(crypto_kdf_derive_from_key(64, 1, '__auth__', :'kdfkey'::bytea)) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 64, 'kdf byte derived subkey');

SELECT length(crypto_kdf_derive_from_key(32, 1, '__auth__', :'kdfkey'::bytea)) kdfsubkeylen \gset
SELECT is(:kdfsubkeylen, 32, 'kdf 32 byte derived subkey');

SELECT is(crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'::bytea),
    crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'::bytea), 'kdf subkeys are deterministic.');

SELECT throws_ok($$SELECT crypto_kdf_derive_from_key(NULL, 2, '__aut__', 'bad'::bytea)$$,
    '22000', 'pgsodium_crypto_kdf_derive_from_key: subkey size cannot be NULL',
    'kdf null key size.');

SELECT throws_ok($$SELECT crypto_kdf_derive_from_key(32, NULL, '__aut__', 'bad'::bytea)$$,
    '22000', 'pgsodium_crypto_kdf_derive_from_key: subkey id cannot be NULL',
    'kdf null key size.');

SELECT throws_ok($$SELECT crypto_kdf_derive_from_key(32, 1, NULL, 'bad'::bytea)$$,
    '22000', 'pgsodium_crypto_kdf_derive_from_key: subkey context cannot be NULL',
    'kdf null key size.');

SELECT throws_ok($$SELECT crypto_kdf_derive_from_key(32, 1, '__aut__', NULL::bytea)$$,
    '22000', 'pgsodium_crypto_kdf_derive_from_key: primary key cannot be NULL',
    'kdf null key size.');

\if :serverkeys

select id as kdf_key_id from create_key('kdf') \gset
SELECT lives_ok(format($$select crypto_kdf_derive_from_key(32, 42, 'pgsodium', %L::uuid)$$, :'kdf_key_id'),
          'crypto_kdf_derive_from_key by uuid');

\endif
