BEGIN;
SELECT plan(4);

SELECT lives_ok($$SELECT randombytes_random()$$, 'randombytes_random');
SELECT lives_ok($$SELECT randombytes_uniform(10)$$, 'randombytes_uniform');
SELECT lives_ok($$SELECT randombytes_buf(10)$$, 'randombytes_buf');
SELECT randombytes_new_seed() bufseed \gset
SELECT lives_ok(format($$SELECT randombytes_buf_deterministic(10, %L)$$, :'bufseed'),
        'randombytes_buf_deterministic');
SELECT * FROM finish();
ROLLBACK;
