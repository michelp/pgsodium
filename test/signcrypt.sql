
BEGIN;
SELECT plan(4);

SELECT crypto_secretbox_noncegen() secretboxnonce \gset

select public, secret from crypto_signcrypt_new_kepair() \gset bob_
select public, secret from crypto_signcrypt_new_kepair() \gset alice_

select state, shared_key from crypto_signcrypt_sign_before('bob', 'alice', :'bob_secret', :'alice_public', 'additional data') \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'shared_key'::bytea) secretbox \gset

select crypto_signcrypt_sign_after(:'state', :'bob_secret', :'secretbox') signature \gset

select state as vstate, shared_key as vkey from
    crypto_signcrypt_verify_before(:'signature', 'bob', 'alice', 'additional data', :'bob_public', :'alice_secret') \gset

select is(:'vkey'::bytea, :'shared_key'::bytea, 'signcrypt shared keys match');

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'vkey'::bytea),
          'bob is your uncle', 'crypto_aead_ietf_decrypt with signcrypt key');

select is(crypto_signcrypt_verify_after(:'vstate', :'signature', :'bob_public', :'secretbox'),
    true, 'signcrypt_verify_after');

select is(crypto_signcrypt_verify_public(:'signature', 'bob', 'alice', 'additional data', :'bob_public', :'secretbox'),
    true, 'signcrypt_verify_public');


SELECT * FROM finish();
ROLLBACK;

-- \if :serverkeys

-- BEGIN;
-- SELECT plan(1);


-- SELECT * FROM finish();
-- ROLLBACK;
-- \endif

