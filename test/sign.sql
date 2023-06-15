
SELECT lives_ok($$select crypto_sign_seed_new_keypair(crypto_sign_new_seed())$$,
                'crypto_sign_seed_new_keypair');

SELECT throws_ok($$select crypto_sign_seed_new_keypair('bogus')$$, '22000',
                 'pgsodium_crypto_sign_seed_keypair: invalid seed',
                 'crypto_sign_seed_new_keypair invalid seed');

SELECT throws_ok($$select crypto_sign_seed_new_keypair(NULL)$$, '22000',
                 'pgsodium_crypto_sign_seed_keypair: seed cannot be NULL',
                 'crypto_sign_seed_new_keypair NULL seed');

SELECT public, secret FROM crypto_sign_new_keypair() \gset sign_

SELECT crypto_sign('bob is your uncle', :'sign_secret') signed \gset

SELECT throws_ok($$select crypto_sign('bob is your uncle', 's')$$,
       '22000', 'pgsodium_crypto_sign: invalid secret key', 'crypto_sign invalid key');

SELECT throws_ok($$select crypto_sign(NULL, 'bad')$$,
       '22000', 'pgsodium_crypto_sign: message cannot be NULL', 'crypto_sign null message');

SELECT throws_ok($$select crypto_sign('bad', NULL)$$,
       '22000', 'pgsodium_crypto_sign: secretkey cannot be NULL', 'crypto_sign null key');

SELECT is(crypto_sign_open(:'signed', :'sign_public'),
          'bob is your uncle', 'crypto_sign_open');

SELECT throws_ok(format($$select crypto_sign_open(%L, 'bad_key')$$, :'signed'),
                 '22000', 'pgsodium_crypto_sign_open: invalid public key',
                 'crypto_sign_open invalid public key');

SELECT throws_ok(format($$select crypto_sign_open('foo', %L)$$, :'sign_public'),
                 '22000', 'pgsodium_crypto_sign_open: invalid message',
                 'crypto_sign_open invalid message');

SELECT throws_ok($$select crypto_sign_open(NULL, 'bad_key')$$,
                 '22000', 'pgsodium_crypto_sign_open: message cannot be NULL',
                 'crypto_sign_open null public key');

SELECT throws_ok($$select crypto_sign_open('foo', NULL)$$,
                 '22000', 'pgsodium_crypto_sign_open: publickey cannot be NULL',
                 'crypto_sign_open null message');

-- public key signatures
-- We will sign our previously generated sealed box

SELECT throws_ok($$select crypto_sign_detached('foo', 'bar')$$,
                 '22000', 'pgsodium_crypto_sign_detached: invalid secret key',
                 'crypto_sign_detached invalid secret key');

SELECT throws_ok($$select crypto_sign_verify_detached('foo', 'bar', 'bork')$$,
                 '22000', 'pgsodium_crypto_sign_verify_detached: invalid public key',
                 'crypto_sign_verify_detached invalid public key');

SELECT crypto_sign_detached('sealed message', :'sign_secret') detached \gset

SELECT is(crypto_sign_verify_detached(:'detached', 'sealed message', :'sign_public'),
          true, 'crypto_sign_detached/verify');

SELECT is(crypto_sign_verify_detached(:'detached', 'xyzzy', :'sign_public'),
          false, 'crypto_sign_detached/verify (incorrect message)');

-- Check Multi-part messages
WITH parts(msg) AS
  (
    VALUES ('Hello Alice'),
           ('Hello Bob'),
           ('Hello Carol')
  ),
tampered(msg) AS
  (
    VALUES ('Hello Alice'),
           ('Hello Bob'),
           ('Hello CaRol')
  ),
prep1 AS
  (
    -- First form of aggregate
    SELECT crypto_sign_update_agg(p.msg::bytea) state
      FROM parts p
  ),
prep2 AS
  (
    -- Second form of aggregate
    SELECT crypto_sign_update_agg(crypto_sign_init(), p.msg::bytea) state
      FROM parts p
  ),
prepv AS
  (
    -- Second form of aggregate from tampered parts
    SELECT crypto_sign_update_agg(crypto_sign_init(), t.msg::bytea) state
      FROM tampered t
  ),
sig AS
  (
    SELECT crypto_sign_final_create(p.state, :'sign_secret') as sig
      FROM prep1 p
  ),
verify AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prep1 p
     CROSS JOIN sig s
  ),
verify2 AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prep2 p
     CROSS JOIN sig s
  ),
noverify AS
  (
    SELECT crypto_sign_final_verify(p.state, s.sig, :'sign_public') as verify
      FROM prepv p
     CROSS JOIN sig s
  )
SELECT ok(verify, 'Multi-part signature')
  FROM verify
UNION ALL
SELECT ok(verify, 'Multi-part signature(2)')
  FROM verify2
-- UNION ALL
-- -- Each time we generate state it will be different, even though sig
-- -- can be verified.
-- SELECT isnt(p1.state, p2.state, 'Multi-part states differ')
--   FROM prep1 p1 CROSS JOIN prep2 p2
UNION ALL
SELECT ok(not verify, 'Multi-part signature detects tampering')
  FROM noverify;

