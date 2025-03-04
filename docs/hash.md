# Hashing Data

``` postgres-console
NOTICE:  extension "pgsodium" already exists, skipping
```

libsodium provides functions for "generic" and "short" hashing.

Generic hashing is suitable for cryptographic purposes using the BLAKE2b algorithm.
``` postgres-console
select pgsodium.crypto_generichash('this is a message');
┌────────────────────────────────────────────────────────────────────┐
│                         crypto_generichash                         │
├────────────────────────────────────────────────────────────────────┤
│ \x9d4a63e5dc1d77ed99b6f756920edb89dfdad27c4a21f2a96a85824b8fdb5fe1 │
└────────────────────────────────────────────────────────────────────┘
(1 row)

select pgsodium.crypto_generichash_keygen() generickey \gset
select pgsodium.crypto_generichash('this is a message'::bytea, :'generickey'::bytea);
┌────────────────────────────────────────────────────────────────────┐
│                         crypto_generichash                         │
├────────────────────────────────────────────────────────────────────┤
│ \xd133a9f3cde8649b62291dd5d794c322a4840577ba330cf2dab29f4ab35908ef │
└────────────────────────────────────────────────────────────────────┘
(1 row)

```
## Short Hashing

Many applications and programming language implementations were
recently found to be vulnerable to denial-of-service (DoS) attacks
when a hash function with weak security guarantees, such as
MurmurHash3, was used to construct a hash table.

To address this, Sodium provides the crypto_shorthash() function,
which outputs short but unpredictable (without knowing the secret key)
values suitable for picking a list in a hash table for a given key.

This function is optimized for short inputs.

The output of this function is only 64 bits. Therefore, it should not
be considered collision-resistant.

Use cases:
- Hash tables
- Probabilistic data structures, such as Bloom filters
- Integrity checking in interactive protocols
``` postgres-console
select pgsodium.crypto_shorthash_keygen() shortkey \gset
select pgsodium.crypto_shorthash('this is a message'::bytea, :'shortkey'::bytea);
┌────────────────────┐
│  crypto_shorthash  │
├────────────────────┤
│ \x4e25dcaba4aedda3 │
└────────────────────┘
(1 row)

```