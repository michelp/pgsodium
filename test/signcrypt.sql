
SELECT crypto_secretbox_noncegen() secretboxnonce \gset

SELECT public, secret FROM crypto_signcrypt_new_keypair() \gset bob_
SELECT public, secret FROM crypto_signcrypt_new_keypair() \gset alice_

SELECT state, shared_key FROM crypto_signcrypt_sign_before('bob', 'alice', :'bob_secret', :'alice_public', 'additional data') \gset

SELECT crypto_secretbox('bob is your uncle', :'secretboxnonce', :'shared_key'::bytea) secretbox \gset

SELECT crypto_signcrypt_sign_after(:'state', :'bob_secret', :'secretbox') signature \gset

SELECT state AS vstate, shared_key AS vkey FROM
    crypto_signcrypt_verify_before(:'signature', 'bob', 'alice', 'additional data', :'bob_public', :'alice_secret') \gset

SELECT is(:'vkey'::bytea, :'shared_key'::bytea, 'signcrypt shared keys match');

SELECT is(crypto_secretbox_open(:'secretbox', :'secretboxnonce', :'vkey'::bytea),
          'bob is your uncle', 'crypto_aead_ietf_decrypt with signcrypt key');

SELECT is(crypto_signcrypt_verify_after(:'vstate', :'signature', :'bob_public', :'secretbox'),
    true, 'signcrypt_verify_after');

SELECT is(crypto_signcrypt_verify_public(:'signature', 'bob', 'alice', 'additional data', :'bob_public', :'secretbox'),
    true, 'signcrypt_verify_public');


