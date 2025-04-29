#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_box_seal_open);
Datum
pgsodium_crypto_box_seal_open (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *ciphertext;
	bytea      *public_key;
	bytea      *secret_key;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: public_key cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: secret_key cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);
	public_key = PG_GETARG_BYTEA_PP (1);
	secret_key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (public_key) != crypto_box_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (secret_key) != crypto_box_SECRETKEYBYTES,
		"%s: invalid secret key");
	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <= crypto_box_SEALBYTES,
		"%s: invalid message");

	result_size = VARSIZE (ciphertext) - crypto_box_SEALBYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_box_seal_open (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext),
		PGSODIUM_UCHARDATA_ANY (public_key),
		PGSODIUM_UCHARDATA_ANY (secret_key));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
