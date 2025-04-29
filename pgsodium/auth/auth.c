#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth);
Datum
pgsodium_crypto_auth (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	int         result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_KEYBYTES,
		"%s: invalid key");
	result_size = VARHDRSZ + crypto_auth_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
