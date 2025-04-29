#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign);
Datum
pgsodium_crypto_sign (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *secretkey;
	unsigned long long signed_message_len;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	secretkey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	result_size = crypto_sign_BYTES + VARSIZE_ANY (message);
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign (
		PGSODIUM_UCHARDATA (result),
		&signed_message_len,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
