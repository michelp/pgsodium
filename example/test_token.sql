create extension if not exists pgsodium;
\ir token.sql
	
select * from pgsodium.crypto_signcrypt_new_keypair() \gset bob_
select * from pgsodium.crypto_signcrypt_new_keypair() \gset alice_

select crypto_signcrypt_token_encrypt('bob', 'alice', :'bob_secret', :'alice_public', 'hi', 'there') token \gset

select :'token';

select * from crypto_signcrypt_token_decrypt(:'token', :'bob_public', :'alice_secret');

select crypto_signcrypt_token_verify(:'token', :'bob_public');
