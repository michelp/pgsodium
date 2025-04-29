#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_by_id);
Datum
pgsodium_crypto_auth_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	int         result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);

	key = pgsodium_derive_helper (key_id, crypto_auth_KEYBYTES, context);
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
