#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_decrypt);
Datum
pgsodium_crypto_aead_det_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	bytea      *key;
	size_t      result_len;
	bytea      *result, *nonce;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
			 crypto_aead_det_xchacha20_ABYTES, "%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_aead_det_xchacha20_KEYBYTES,
			 "%s: invalid key");
	result_len =
		VARSIZE_ANY_EXHDR (ciphertext) - crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_len + VARHDRSZ);
	if (!PG_ARGISNULL (3))
	{
		nonce = PG_GETARG_BYTEA_P (3);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
				 crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}
	success = crypto_aead_det_xchacha20_decrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	PG_RETURN_BYTEA_P (result);
}
