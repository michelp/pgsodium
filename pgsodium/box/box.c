/* doctest/box
-- # Public Key Cryptography
--
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
--
-- The `box` API uses public key encryption
-- to securely send messages between two parties who only know each
-- others public keys.  Each party has a secret key that is used to
-- encrypt messages.
--
-- [Libsodium Documentation](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
--
-- `crypto_box_new_keypair()` returns a new, randomly generated, pair of
-- keys for public key encryption.  The public key can be shared with
-- anyone.  The secret key must never be shared.
--
-- `crypto_box_noncegen()` generates a random nonce which will be used
-- when encrypting messages.  For security, each nonce must be used only
-- once, though it is not a secret.  The purpose of the nonce is to add
-- randomness to the message so that the same message encrypted multiple
-- times with the same key will produce different ciphertexts.
--
-- `crypto_box()` encrypts a message using a nonce, the intended
-- recipient's public key and the sender's secret key.  The resulting
-- ciphertext can only be decrypted by the intended recipient using their
-- secret key.  The nonce must be sent along with the ciphertext.
--
-- `crypto_box_open()` descrypts a ciphertext encrypted using
-- `crypto_box()`.  It takes the ciphertext, nonce, the sender's public
-- key and the recipient's secret key as parameters, and returns the
-- original message.  Note that the recipient should ensure that the
-- public key belongs to the sender.
--
--
-- Public key encryption requires each party have a pair of keys, one
-- public and one private, and a nonce.  The nonce doesn't have to be
-- confidential, but it should never ever be reused with the same
-- key. The easiest way to generate a nonce is to use
-- `crypto_box_noncegen`:

select crypto_box_new_seed() seed \gset
SELECT pgsodium.crypto_box_noncegen() nonce \gset

-- Now create a new keypair for both bob and alice.

SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_seed_new_keypair(:'seed') \gset alice_

SELECT pgsodium.crypto_box('hello bob', :'nonce', :'bob_public', :'alice_secret') atob \gset
SELECT :'atob';

select convert_from(pgsodium.crypto_box_open(:'atob', :'nonce', :'alice_public', :'bob_secret'), 'utf8');

-- Sealed boxes are designed to anonymously send messages to a recipient
-- given its public key.
--
-- Only the recipient can decrypt these messages, using its private
-- key. While the recipient can verify the integrity of the message, it
-- cannot verify the identity of the sender.
--
-- A message is encrypted using an ephemeral key pair, whose secret part
-- is destroyed right after the encryption process.
--
-- Without knowing the secret key used for a given message, the sender
-- cannot decrypt its own message later. And without additional data, a
-- message cannot be correlated with the identity of its sender.

SELECT pgsodium.crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset
SELECT convert_from(pgsodium.crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret'), 'utf8');

*/

#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_box);
Datum
pgsodium_crypto_box (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *nonce;
	bytea      *publickey;
	bytea      *secretkey;
	int         success;
	size_t      message_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	publickey = PG_GETARG_BYTEA_PP (2);
	secretkey = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_box_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_box_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_box_SECRETKEYBYTES,
		"%s: invalid secret key");

	message_size = crypto_box_MACBYTES + VARSIZE_ANY (message);
	result = _pgsodium_zalloc_bytea (message_size);
	success = crypto_box_easy (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (nonce),
		PGSODIUM_UCHARDATA_ANY (publickey),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

