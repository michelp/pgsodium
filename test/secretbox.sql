BEGIN;
SELECT plan(4);

SELECT crypto_secretbox_keygen() boxkey \gset
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'boxkey'::bytea) secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'boxkey'::bytea),
          'bob is your uncle', 'secretbox_open');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, 'bad nonce', %L::bytea)$$, :'secretbox', :'boxkey'),
	   	         '22000', 'invalid nonce', 'crypto_secretbox_open invalid nonce');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, %L, 'bad_key'::bytea)$$, :'secretbox', :'secretboxnonce'),
	   	         '22000', 'invalid key', 'crypto_secretbox_open invalid key');

SELECT throws_ok(format($$select crypto_secretbox_open('foo', %L, %L::bytea)$$, :'secretboxnonce', :'boxkey'),
	   	         '22000', 'invalid message', 'crypto_secretbox_open invalid message');

SELECT * FROM finish();
ROLLBACK;

\if :serverkeys

BEGIN;
SELECT plan(1);

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', 1) secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', 1),
          'bob is your uncle', 'secretbox_open by id');

SELECT * FROM finish();
ROLLBACK;
\endif
