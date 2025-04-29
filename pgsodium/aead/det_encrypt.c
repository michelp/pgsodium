#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_encrypt);
Datum
pgsodium_crypto_aead_det_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *key;
	bytea      *nonce;
	size_t      result_size;
	bytea      *result;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);

	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_aead_det_xchacha20_KEYBYTES,
			 "%s: invalid key");
	if (!PG_ARGISNULL (3))
	{
		nonce = PG_GETARG_BYTEA_PP (3);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
				 crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}
	result_size =
		VARSIZE_ANY_EXHDR (message) + crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);
	success = crypto_aead_det_xchacha20_encrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: crypto_aead_det_xchacha20_encrypt failed");
	PG_RETURN_BYTEA_P (result);
}
