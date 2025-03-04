# Public Key Cryptography


The `box` API uses public key encryption
to securely send messages between two parties who only know each
others public keys.  Each party has a secret key that is used to
encrypt messages.

[Libsodium Documentation](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)

`crypto_box_new_keypair()` returns a new, randomly generated, pair of
keys for public key encryption.  The public key can be shared with
anyone.  The secret key must never be shared.

`crypto_box_noncegen()` generates a random nonce which will be used
when encrypting messages.  For security, each nonce must be used only
once, though it is not a secret.  The purpose of the nonce is to add
randomness to the message so that the same message encrypted multiple
times with the same key will produce different ciphertexts.

`crypto_box()` encrypts a message using a nonce, the intended
recipient's public key and the sender's secret key.  The resulting
ciphertext can only be decrypted by the intended recipient using their
secret key.  The nonce must be sent along with the ciphertext.

`crypto_box_open()` descrypts a ciphertext encrypted using
`crypto_box()`.  It takes the ciphertext, nonce, the sender's public
key and the recipient's secret key as parameters, and returns the
original message.  Note that the recipient should ensure that the
public key belongs to the sender.


Public key encryption requires each party have a pair of keys, one
public and one private, and a nonce.  The nonce doesn't have to be
confidential, but it should never ever be reused with the same
key. The easiest way to generate a nonce is to use
`crypto_box_noncegen`:
``` postgres-console
select crypto_box_new_seed() seed \gset
SELECT pgsodium.crypto_box_noncegen() nonce \gset
```
Now create a new keypair for both bob and alice.
``` postgres-console
SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_seed_new_keypair(:'seed') \gset alice_
SELECT pgsodium.crypto_box('hello bob', :'nonce', :'bob_public', :'alice_secret') atob \gset
SELECT :'atob';
┌──────────────────────────────────────────────────────┐
│                       ?column?                       │
├──────────────────────────────────────────────────────┤
│ \x7fdd158c74cc98a57abcc69eaf2c83e48e3e46150a018b2e4e │
└──────────────────────────────────────────────────────┘
(1 row)

select pgsodium.crypto_box_open(:'atob', :'nonce', :'alice_public', :'bob_secret');
┌──────────────────────┐
│   crypto_box_open    │
├──────────────────────┤
│ \x68656c6c6f20626f62 │
└──────────────────────┘
(1 row)

```
Sealed boxes are designed to anonymously send messages to a recipient
given its public key.

Only the recipient can decrypt these messages, using its private
key. While the recipient can verify the integrity of the message, it
cannot verify the identity of the sender.

A message is encrypted using an ephemeral key pair, whose secret part
is destroyed right after the encryption process.

Without knowing the secret key used for a given message, the sender
cannot decrypt its own message later. And without additional data, a
message cannot be correlated with the identity of its sender.
``` postgres-console
SELECT pgsodium.crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset
SELECT pgsodium.crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret');
┌──────────────────────────────────────┐
│         crypto_box_seal_open         │
├──────────────────────────────────────┤
│ \x626f6220697320796f757220756e636c65 │
└──────────────────────────────────────┘
(1 row)

```