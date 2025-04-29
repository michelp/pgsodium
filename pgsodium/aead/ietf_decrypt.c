#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_decrypt);
Datum
pgsodium_crypto_aead_ietf_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	bytea      *nonce;
	bytea      *key;
	size_t      ciphertext_len;
	unsigned long long result_size;
	bytea      *result;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_PP (2);
	key = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
			 crypto_aead_chacha20poly1305_IETF_ABYTES, "%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			 crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) !=
			 crypto_aead_chacha20poly1305_IETF_KEYBYTES, "%s: invalid key");

	ciphertext_len = VARSIZE_ANY_EXHDR (ciphertext);
	result = _pgsodium_zalloc_bytea (
		ciphertext_len + VARHDRSZ - crypto_aead_chacha20poly1305_IETF_ABYTES);

	success =
		crypto_aead_chacha20poly1305_ietf_decrypt (
			PGSODIUM_UCHARDATA (result),
			&result_size,
			NULL,
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			ciphertext_len,
			associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
			associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
			PGSODIUM_UCHARDATA_ANY (nonce),
			PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	PG_RETURN_BYTEA_P (result);
}
