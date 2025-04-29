#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_open);
Datum
pgsodium_crypto_sign_open (PG_FUNCTION_ARGS)
{
	int         success;
	unsigned long long unsigned_message_len;
	bytea      *message;
	bytea      *publickey;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: publickey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	publickey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_sign_BYTES,
		"%s: invalid message");

	result_size = VARSIZE_ANY (message) - crypto_sign_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign_open (
		PGSODIUM_UCHARDATA (result),
		&unsigned_message_len,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (publickey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
