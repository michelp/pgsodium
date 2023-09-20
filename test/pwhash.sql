
SELECT lives_ok($$SELECT crypto_pwhash_saltgen()$$, 'crypto_pwhash_saltgen');

SELECT is(crypto_pwhash('Correct Horse Battery Staple', '\xccfe2b51d426f88f6f8f18c24635616b'),
        '\x77d029a9b3035c88f186ed0f69f58386ad0bd5252851b4e89f0d7057b5081342',
        'crypto_pwhash');

select throws_ok($$select crypto_pwhash(NULL, 'bad')$$,
    '22000', 'pgsodium_crypto_pwhash: data cannot be NULL', 'crypto_pwhash NULL password');

select throws_ok($$select crypto_pwhash('bad', NULL)$$,
    '22000', 'pgsodium_crypto_pwhash: salt cannot be NULL', 'crypto_pwhash NULL salt');

SELECT ok(crypto_pwhash_str_verify(crypto_pwhash_str('Correct Horse Battery Staple'),
          'Correct Horse Battery Staple'),
          'crypto_pwhash_str_verify');

select throws_ok($$select crypto_pwhash_str(NULL)$$,
    '22000', 'pgsodium_crypto_pwhash_str: password cannot be NULL', 'crypto_pwhash_str NULL password');

select throws_ok($$select crypto_pwhash_str_verify(NULL, 'bad')$$,
    '22000', 'pgsodium_crypto_pwhash_str_verify: hashed password cannot be NULL', 'crypto_pwhash_str_verify NULL hash');

select throws_ok($$select crypto_pwhash_str_verify('bad', NULL)$$,
    '22000', 'pgsodium_crypto_pwhash_str_verify: password cannot be NULL', 'crypto_pwhash_str_verify NULL password');

