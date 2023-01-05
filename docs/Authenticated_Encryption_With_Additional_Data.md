# Authenticated Encryption with Associated Data

Authenticated Encryption with Associated Data (AEAD) is a form of [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) that associated an unencrypted plaintext along with the [authentication signature](https://en.wikipedia.org/wiki/Digital_signature) computed for the encrypted cyphertext.  In a sense one signature "covers" both the encrypted and unencrypted portion of a message.  For example, an application may want to encrypt a credit card number for payment, but then associate an account id with that credit card number, so that the credit card number can only be decrypted in the correct account number is provided as well.  This prevents substitution attacks where an different account number could be swapped in to cause payment to be charged to a different card.  pgsodium currently provides two AEAD constructions from libsodium:

- The [crypto_aead_ietf](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction) API.
- The [crypto_aead_det](https://github.com/jedisct1/libsodium-xchacha20-siv) API.

## crypto_aead_ietf

The IETF variant of the ChaCha20-Poly1305 construction can safely encrypt a practically unlimited number of messages, but individual messages cannot exceed 64*(2^32)-64 bytes (approximatively 256 GiB).

### `crypto_aead_ietf_keygen()`

Creates a cryptographically random key for IETF AEAD.

### `crypto_aead_ietf_noncegen()`

Creates a cryptographically random nonce for IETF AEAD.

### `crypto_aead_ietf_encrypt()`

Encrypt and Authenticate a message with the given key and associated data.  This function only returns the encrypted and signed confidential part, it is up to the caller to preserve the non-confidential part. 

### `crypto_aead_ietf_decrypt()`

Decrypt a ciphertext with the provided key and associated data.


## crypto_aead_det

Deterministic/nonce-reuse resistant authenticated encryption scheme using XChaCha20, implemented on libsodium.

### `crypto_aead_det_keygen()`

Creates a cryptographically random key for deterministic AEAD.

### `crypto_aead_det_noncegen()`

Creates a cryptographically random nonce for deterministic AEAD.

### `crypto_aead_det_encrypt()`

Encrypt and Authenticate a message with the given key and associated data.  This function only returns the encrypted and signed confidential part, it is up to the caller to preserve the non-confidential part. 

### `crypto_aead_det_decrypt()`

Decrypt a ciphertext with the provided key and associated data.

