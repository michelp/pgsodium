BEGIN;
SELECT plan(1);

select public, secret from pgsodium.crypto_signcrypt_new_keypair() \gset bob_
select public, secret from pgsodium.crypto_signcrypt_new_keypair() \gset alice_

select * from pgsodium.crypto_signcrypt_token_encrypt(
	'bob', 'alice', :'bob_secret', :'alice_public', 'hi', 'there') \gset token_

select results_eq(
  format($$select
  sender,
  receiver,
  message,
  additional,
  shared_key = %L
  from pgsodium.crypto_signcrypt_token_decrypt(%L, %L, %L)$$,
  :shared_key', :'token_token', :'bob_public', :'alice_secret'),
  $$values ('bob', 'alice', 'hi', 'there', true)$$,
  'signcryption decryption');

select ok(pgsodium.crypto_signcrypt_token_verify(:'token_token', :'bob_public'),
	'signcryption verify');

SELECT * FROM finish();
ROLLBACK;
	
