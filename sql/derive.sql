\pset linestyle unicode
\pset border 2
\pset pager off
-- # Key Derivation
--
-- Multiple secret subkeys can be derived from a single master key.
--
-- Given the master key and a key identifier, a subkey can be
-- deterministically computed. However, given a subkey, an attacker
-- cannot compute the master key nor any other subkeys.
--
-- The crypto_kdf API can derive up to 2^64 keys from a single master key
-- and context, and individual subkeys can have an arbitrary length
-- between 128 (16 bytes) and 512 bits (64 bytes).

select pgsodium.derive_key(42);

select pgsodium.derive_key(42, 64, 'foozbarz');

