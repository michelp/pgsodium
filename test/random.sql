
SELECT lives_ok($$SELECT randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT randombytes_buf(10)$$, 'randombytes_buf');

SELECT throws_ok($$SELECT randombytes_uniform(NULL)$$,
    '22000', 'pgsodium_randombytes_uniform: upper bound cannot be NULL', 'randombytes_uniform NULL bound');

SELECT throws_ok($$SELECT randombytes_buf(NULL)$$,
    '22000', 'pgsodium_randombytes_buf: buffer size cannot be NULL', 'randombytes_buf NULL size');

SELECT randombytes_new_seed() bufseed \gset

SELECT lives_ok(format($$SELECT randombytes_buf_deterministic(10, %L)$$, :'bufseed'),
        'randombytes_buf_deterministic');

SELECT throws_ok($$SELECT randombytes_buf_deterministic(NULL, 'bad')$$,
    '22000', 'pgsodium_randombytes_buf_deterministic: buffer size cannot be NULL',  'randombytes_buf_deterministic NULL size');

SELECT throws_ok($$SELECT randombytes_buf_deterministic(10, NULL)$$,
    '22000', 'pgsodium_randombytes_buf_deterministic: seed cannot be NULL',  'randombytes_buf_deterministic NULL seed');

