#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_encrypt);
Datum
pgsodium_crypto_aead_ietf_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *nonce;
	bytea      *key;
	unsigned long long result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
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

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			 crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) !=
			 crypto_aead_chacha20poly1305_IETF_KEYBYTES, "%s: invalid key");

	result_size = VARSIZE_ANY_EXHDR (message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);
	crypto_aead_chacha20poly1305_ietf_encrypt (
		PGSODIUM_UCHARDATA (result),
		&result_size,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		NULL,
		PGSODIUM_UCHARDATA_ANY (nonce),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
