# Public Key Cryptography

The `box` API uses public key encryption to securely send messages between two parties who only know each others public keys.  Each party has a secret key that is used to encrypt messages.

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




```python
%load_ext sql
```


```python
%config SqlMagic.feedback=False
%config SqlMagic.displaycon=False
%sql postgresql://postgres@/
%sql CREATE EXTENSION IF NOT EXISTS pgsodium;
```




    []



Public key ncryption requires each party have a pair of keys, one public and one private, and a nonce.  The nonce doesn't have to be confidential, but it should never ever be reused with the same key. The easiest way to generate a nonce is to use `crypto_secretbox_noncegen`:


```python
nonce = %sql SELECT crypto_box_noncegen::text from pgsodium.crypto_box_noncegen()
nonce = nonce[0][0]
```

Now create a new keypair for both bob and alice.  


```python
bob = %sql SELECT public::text, secret::text FROM pgsodium.crypto_box_new_keypair()
bob_public, bob_secret = bob[0]

alice = %sql SELECT public::text, secret::text FROM pgsodium.crypto_box_new_keypair()
alice_public, alice_secret = bob[0]
```

Bob and alice now exchange public their public keys.  How this happens is outside the scope of pgsodium.

## Encryption

Alice can encrypt a message to Bob with her keypair and Bob's public key.


```python
box = %sql SELECT crypto_box::text FROM pgsodium.crypto_box('hello bob', :nonce, :bob_public, :alice_secret)
box = box[0][0]
print('Encrypted message from Alice to Bob is: ', box)
```

    Encrypted message from Alice to Bob is:  \xdc9fd86dfe2a909706a99b0baa99470f44668f497a1e00a06c


## Decryption



```python
message = %sql select crypto_box_open FROM pgsodium.crypto_box_open(:box, :nonce, :alice_public, :bob_secret)
message = message[0][0]
print('Verified message is: ', message.tobytes().decode('utf8'))
```

    Verified message is:  hello bob


# Sealed Boxes

Sealed boxes are designed to anonymously send messages to a recipient given its public key.

Only the recipient can decrypt these messages, using its private key. While the recipient can verify the integrity of the message, it cannot verify the identity of the sender.

A message is encrypted using an ephemeral key pair, whose secret part is destroyed right after the encryption process.

Without knowing the secret key used for a given message, the sender cannot decrypt its own message later. And without additional data, a message cannot be correlated with the identity of its sender.


```python
sealed = %sql SELECT crypto_box_seal::text FROM pgsodium.crypto_box_seal('bob is your uncle', :bob_public)
sealed = sealed[0][0]

message = %sql SELECT pgsodium.crypto_box_seal_open(:sealed, :bob_public, :bob_secret)
message = message[0][0]
print('The sealed message is: ', message.tobytes().decode('utf8'))
```

    The sealed message is:  bob is your uncle

