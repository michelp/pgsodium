#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_encrypt_by_id);
Datum
pgsodium_crypto_aead_ietf_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *nonce;
	unsigned long long key_id;
	bytea      *context;
	unsigned long long result_size;
	bytea      *result;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_P (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_P (2);
	key_id = PG_GETARG_INT64 (3);
	context = PG_GETARG_BYTEA_P (4);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			 crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	key =
		pgsodium_derive_helper (key_id,
								crypto_aead_chacha20poly1305_IETF_KEYBYTES, context);
	result_size =
		VARSIZE_ANY (message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_aead_chacha20poly1305_ietf_encrypt (PGSODIUM_UCHARDATA (result),
											   &result_size,
											   PGSODIUM_UCHARDATA (message),
											   VARSIZE_ANY_EXHDR (message),
											   associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
											   associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
											   NULL, PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	SET_VARSIZE (result,
				 VARHDRSZ + result_size + crypto_aead_chacha20poly1305_IETF_ABYTES);
	PG_RETURN_BYTEA_P (result);
}
