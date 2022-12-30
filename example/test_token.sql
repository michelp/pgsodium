create extension if not exists pgsodium;
\ir token.sql
	
select * from pgsodium.crypto_signcrypt_new_keypair() \gset bob_
select * from pgsodium.crypto_signcrypt_new_keypair() \gset alice_

\x
select * from pgsodium.crypto_signcrypt_token_encrypt('bob', 'alice', :'bob_secret', :'alice_public', 'hi', 'there') \gset token_

select :'token_secret_key';
select :'token_token';

select * from pgsodium.crypto_signcrypt_token_decrypt(:'token_token', :'bob_public', :'alice_secret');

select * from pgsodium.crypto_signcrypt_token_verify(:'token_token', :'bob_public');
