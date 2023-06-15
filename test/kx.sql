
SELECT public, secret FROM crypto_kx_new_keypair() \gset bob_
SELECT public, secret FROM crypto_kx_new_keypair() \gset alice_

SELECT crypto_kx_new_seed() kxseed \gset

SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_bob_
SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_alice_

select throws_ok($$select crypto_kx_client_session_keys(NULL, 'bad', 'bad')$$,
    '22000', 'pgsodium_crypto_kx_client_session_keys: client publickey cannot be NULL', 'kx client null client pk');

select throws_ok($$select crypto_kx_client_session_keys('bad', NULL, 'bad')$$,
    '22000', 'pgsodium_crypto_kx_client_session_keys: client secretkey cannot be NULL', 'kx client null client sk');

select throws_ok($$select crypto_kx_client_session_keys('bad', 'bad', NULL)$$,
    '22000', 'pgsodium_crypto_kx_client_session_keys: server publickey cannot be NULL', 'kx client null server pk');

select throws_ok($$select crypto_kx_server_session_keys(NULL, 'bad', 'bad')$$,
    '22000', 'pgsodium_crypto_kx_server_session_keys: server publickey cannot be NULL', 'kx server null client pk');

select throws_ok($$select crypto_kx_server_session_keys('bad', NULL, 'bad')$$,
    '22000', 'pgsodium_crypto_kx_server_session_keys: server secretkey cannot be NULL', 'kx server null client sk');

select throws_ok($$select crypto_kx_server_session_keys('bad', 'bad', NULL)$$,
    '22000', 'pgsodium_crypto_kx_server_session_keys: client publickey cannot be NULL', 'kx server null server pk');

SELECT tx, rx FROM crypto_kx_client_session_keys(
    :'seed_bob_public', :'seed_bob_secret',
    :'seed_alice_public') \gset session_bob_

SELECT tx, rx FROM crypto_kx_server_session_keys(
    :'seed_alice_public', :'seed_alice_secret',
    :'seed_bob_public') \gset session_alice_

SELECT crypto_secretbox('hello alice', :'secretboxnonce', :'session_bob_tx'::bytea) bob_to_alice \gset

SELECT is(crypto_secretbox_open(:'bob_to_alice', :'secretboxnonce', :'session_alice_rx'::bytea),
          'hello alice', 'secretbox_open session key');

SELECT crypto_secretbox('hello bob', :'secretboxnonce', :'session_alice_tx'::bytea) alice_to_bob \gset

SELECT is(crypto_secretbox_open(:'alice_to_bob', :'secretboxnonce', :'session_bob_rx'::bytea),
          'hello bob', 'secretbox_open session key');

