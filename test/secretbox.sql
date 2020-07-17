BEGIN;
SELECT plan(4);

SELECT crypto_secretbox_keygen() boxkey \gset
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'boxkey') secretbox \gset

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'boxkey'),
          'bob is your uncle', 'secretbox_open');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, 'bad nonce', %L)$$, :'secretbox', :'boxkey'),
	   	         '22000', 'invalid nonce', 'crypto_secretbox_open invalid nonce');

SELECT throws_ok(format($$select crypto_secretbox_open(%L, %L, 'bad_key')$$, :'secretbox', :'secretboxnonce'),
	   	         '22000', 'invalid key', 'crypto_secretbox_open invalid key');

SELECT throws_ok(format($$select crypto_secretbox_open('foo', %L, %L)$$, :'secretboxnonce', :'boxkey'),
	   	         '22000', 'invalid message', 'crypto_secretbox_open invalid message');

SELECT * FROM finish();
ROLLBACK;

