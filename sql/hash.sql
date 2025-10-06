-- # Hashing Data
--
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
--
-- libsodium provides functions for "generic" and "short" hashing.
--
-- Generic hashing is suitable for cryptographic purposes using the BLAKE2b algorithm.

select pgsodium.crypto_generichash('this is a message');

select pgsodium.crypto_generichash_keygen() generickey \gset

select pgsodium.crypto_generichash('this is a message'::bytea, :'generickey'::bytea);

-- ## Short Hashing
--
-- Many applications and programming language implementations were
-- recently found to be vulnerable to denial-of-service (DoS) attacks
-- when a hash function with weak security guarantees, such as
-- MurmurHash3, was used to construct a hash table.
--
-- To address this, Sodium provides the crypto_shorthash() function,
-- which outputs short but unpredictable (without knowing the secret key)
-- values suitable for picking a list in a hash table for a given key.
--
-- This function is optimized for short inputs.
--
-- The output of this function is only 64 bits. Therefore, it should not
-- be considered collision-resistant.
--
-- Use cases:
-- - Hash tables
-- - Probabilistic data structures, such as Bloom filters
-- - Integrity checking in interactive protocols

select pgsodium.crypto_shorthash_keygen() shortkey \gset
select pgsodium.crypto_shorthash('this is a message'::bytea, :'shortkey'::bytea);

