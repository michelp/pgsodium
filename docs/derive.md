# Key Derivation

Multiple secret subkeys can be derived from a single master key.

Given the master key and a key identifier, a subkey can be
deterministically computed. However, given a subkey, an attacker
cannot compute the master key nor any other subkeys.

The crypto_kdf API can derive up to 2^64 keys from a single master key
and context, and individual subkeys can have an arbitrary length
between 128 (16 bytes) and 512 bits (64 bytes).
``` postgres-console
select pgsodium.derive_key(42);
┌────────────────────────────────────────────────────────────────────┐
│                             derive_key                             │
├────────────────────────────────────────────────────────────────────┤
│ \xedb9dad4a157825d64966a45baab5050d8a443084dc2c0b738016eda4a3fabea │
└────────────────────────────────────────────────────────────────────┘
(1 row)

select pgsodium.derive_key(42, 64, 'foozbarz');
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                             derive_key                                                             │
├────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ \xba70d8f39bb7803a1b89e14d949f545ea1a0cc03357368f38c57cfe61b61ecfddfe15957bffb9ded0c85cf0b0a0714f69413cb297c59cb4e4e9d0a55e9032aa0 │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
(1 row)

```