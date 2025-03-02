\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Secret Key Cryptography

select pgsodium.crypto_secretbox_keygen() key \gset

select pgsodium.crypto_secretbox_noncegen() nonce \gset

select pgsodium.crypto_secretbox('bob is your uncle', :'nonce', :'key') secretbox \gset

select pgsodium.crypto_secretbox_open(:'secretbox', :'nonce', :'key');

