#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_detached);
Datum
pgsodium_crypto_sign_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *secretkey;
	size_t      sig_size = crypto_sign_BYTES;
	size_t      result_size = VARHDRSZ + sig_size;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	secretkey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	success = crypto_sign_detached (
		PGSODIUM_UCHARDATA (result),
		NULL,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
