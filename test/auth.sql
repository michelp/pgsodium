BEGIN;
SELECT plan(4);

	
SELECT crypto_auth_keygen() authkey \gset

SELECT crypto_auth('bob is your uncle', :'authkey') auth_mac \gset

SELECT throws_ok($$select crypto_auth('bob is your uncle', 'bad_key')$$,
	             '22000', 'invalid key', 'crypto_auth invalid key');

SELECT ok(crypto_auth_verify(:'auth_mac', 'bob is your uncle', :'authkey'),
          'crypto_auth_verify');
SELECT throws_ok(format($$select crypto_auth_verify('bad mac', 'bob is your uncle', %L)$$, :'authkey'),
	             '22000', 'invalid mac', 'crypto_auth_verify invalid mac');
SELECT throws_ok(format($$select crypto_auth_verify(%L, 'bob is your uncle', 'bad_key')$$, :'auth_mac'),
	             '22000', 'invalid key', 'crypto_auth_verify invalid key');

SELECT * FROM finish();
ROLLBACK;

