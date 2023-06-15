SELECT crypto_secretbox_keygen() boxkey \gset
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'boxkey'::bytea) secretbox \gset

SELECT throws_ok(format($$select crypto_secretbox(%L, 'bad nonce', %L::bytea)$$, :'secretbox', :'boxkey'),
                 '22000', 'pgsodium_crypto_secretbox: invalid nonce', 'crypto_secretbox invalid nonce');

SELECT throws_ok(format($$select crypto_secretbox(%L, %L, 'bad_key'::bytea)$$, :'secretbox', :'secretboxnonce'),
                 '22000', 'pgsodium_crypto_secretbox: invalid key', 'crypto_secretbox invalid key');

SELECT throws_ok($$select crypto_secretbox(NULL, 'bad', 'bad'::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox: message cannot be NULL', 'crypto_secretbox null message');

SELECT throws_ok($$select crypto_secretbox('bad', NULL, 'bad'::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox: nonce cannot be NULL', 'crypto_secretbox null nonce');

SELECT throws_ok($$select crypto_secretbox('bad', 'bad', NULL::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox: key cannot be NULL', 'crypto_secretbox null key');

SELECT throws_ok($$select crypto_secretbox('bad', 'bad', NULL::bigint)$$,
                 '22000', 'pgsodium_crypto_secretbox_by_id: key id cannot be NULL', 'crypto_secretbox null key id');

SELECT throws_ok($$select crypto_secretbox('bad', 'bad', 1, NULL)$$,
                 '22000', 'pgsodium_crypto_secretbox_by_id: key context cannot be NULL', 'crypto_secretbox null key context');

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'boxkey'::bytea),
          'bob is your uncle', 'secretbox_open');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, 'bad nonce', %L::bytea)$$, :'secretbox', :'boxkey'),
                 '22000', 'pgsodium_crypto_secretbox_open: invalid nonce', 'crypto_secretbox_open invalid nonce');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, %L, 'bad_key'::bytea)$$, :'secretbox', :'secretboxnonce'),
                 '22000', 'pgsodium_crypto_secretbox_open: invalid key', 'crypto_secretbox_open invalid key');

SELECT throws_ok(format($$select crypto_secretbox_open('foo', %L, %L::bytea)$$, :'secretboxnonce', :'boxkey'),
                 '22000', 'pgsodium_crypto_secretbox_open: invalid message', 'crypto_secretbox_open invalid message');

SELECT throws_ok($$select crypto_secretbox_open(NULL, 'bad', 'bad'::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox_open: message cannot be NULL', 'crypto_secretbox null message');

SELECT throws_ok($$select crypto_secretbox_open('bad', NULL, 'bad'::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox_open: nonce cannot be NULL', 'crypto_secretbox null nonce');

SELECT throws_ok($$select crypto_secretbox_open('bad', 'bad', NULL::bytea)$$,
                 '22000', 'pgsodium_crypto_secretbox_open: key cannot be NULL', 'crypto_secretbox null key');

SELECT throws_ok($$select crypto_secretbox_open('bad', 'bad', NULL::bigint)$$,
                 '22000', 'pgsodium_crypto_secretbox_open_by_id: key id cannot be NULL', 'crypto_secretbox null key id');

SELECT throws_ok($$select crypto_secretbox_open('bad', 'bad', 1, NULL)$$,
                 '22000', 'pgsodium_crypto_secretbox_open_by_id: key context cannot be NULL', 'crypto_secretbox null key context');

\if :serverkeys

SET ROLE pgsodium_keyiduser;

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', 1) secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', 1),
          'bob is your uncle', 'secretbox_open by id');

SELECT throws_ok($$select crypto_secretbox('secretbox', 'secretboxnonce', 'whatever'::bytea)$$,
                 '42501', 'permission denied for function crypto_secretbox', 'crypto_secretbox denied');

SELECT throws_ok($$select crypto_secretbox_open('secretbox', 'secretboxnonce', 'whatever'::bytea)$$,
                 '42501', 'permission denied for function crypto_secretbox_open', 'crypto_secretbox_open denied');

SELECT id as secretbox_key_id from create_key('secretbox') \gset
SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'secretbox_key_id'::uuid) secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'secretbox_key_id'::uuid),
          'bob is your uncle', 'secretbox_open by id');

RESET ROLE;
\endif
