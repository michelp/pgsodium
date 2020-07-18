BEGIN;
SELECT plan(5);

SELECT crypto_generichash_keygen() generickey \gset

SELECT is(crypto_generichash('bob is your uncle'),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash');

SELECT is(crypto_generichash('bob is your uncle', NULL),
          '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
          'crypto_generichash NULL key');

SELECT lives_ok(format($$select crypto_generichash('bob is your uncle', %L)$$, :'generickey'),
          'crypto_generichash with key');

SELECT crypto_shorthash_keygen() shortkey \gset

SELECT lives_ok(format($$select crypto_shorthash('bob is your uncle', %L)$$, :'shortkey'), 'crypto_shorthash');

SELECT throws_ok($$select crypto_shorthash('bob is your uncle', 's')$$,
	   '22000', 'invalid key', 'crypto_shorthash invalid key');

SELECT * FROM finish();
ROLLBACK;
