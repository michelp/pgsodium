\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Hash-based Message Authentication Codes
--
--
-- [https://en.wikipedia.org/wiki/HMAC]
--
-- In cryptography, an HMAC (sometimes expanded as either keyed-hash
-- message authentication code or hash-based message authentication code)
-- is a specific type of message authentication code (MAC) involving a
-- cryptographic hash function and a secret cryptographic key. As with
-- any MAC, it may be used to simultaneously verify both the data
-- integrity and authenticity of a message.
--
-- [C API Documentation](https://doc.libsodium.org/advanced/hmac-sha2)
--
-- pgsodium provides hmacsha512 and hmacsha256, only 512-bit examples are
-- provided below, the 256-bit API is identical but using names like
-- `crypto_auth_hmacsha256_*`.
--
select pgsodium.crypto_auth_hmacsha512_keygen() hmackey \gset

select pgsodium.crypto_auth_hmacsha512('this is authentic'::bytea, :'hmackey'::bytea) signature \gset

select pgsodium.crypto_auth_hmacsha512_verify(:'signature'::bytea, 'this is authentic'::bytea, :'hmackey'::bytea);

