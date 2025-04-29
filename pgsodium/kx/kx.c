/* doctest/kx
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Key Exchange
--
-- Using the key exchange API, two parties can securely compute a set of
-- shared keys using their peer's public key and their own secret key

select public, secret from pgsodium.crypto_kx_new_keypair() \gset bob_
select public, secret from pgsodium.crypto_kx_new_keypair() \gset alice_

select tx, rx from pgsodium.crypto_kx_client_session_keys(:'bob_public'::bytea, :'bob_secret'::bytea, :'alice_public'::bytea);

select tx, rx from pgsodium.crypto_kx_server_session_keys(:'alice_public'::bytea, :'alice_secret'::bytea, :'bob_public'::bytea)

 */

