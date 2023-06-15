
select is(crypto_hash_sha256('bob is your uncle'),
    '\x5eff82dc2ca0cfbc0d0eaa95b13b7fbec11540e217b0fe2a6f3c7d12f657630d', 'sha256');
select is(crypto_hash_sha512('bob is your uncle'),
    '\xd8adbd01462f1aad1b91a4557d5c865b63dab1b9181cb02f2123f50d210b74a53754a18b09d9f75e38101ce6de04879b35eca91992fade0bb6842f4ea556e952',
    'sha512');

select throws_ok($$ select crypto_hash_sha256(NULL)$$,
    '22000', 'pgsodium_crypto_hash_sha256: message cannot be NULL', 'sha256 NULL data');

select throws_ok($$ select crypto_hash_sha512(NULL)$$,
    '22000', 'pgsodium_crypto_hash_sha512: message cannot be NULL', 'sha512 NULL data');

