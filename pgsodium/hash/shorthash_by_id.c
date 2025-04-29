#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_shorthash_by_id);
Datum
pgsodium_crypto_shorthash_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *key;
	bytea      *context;
	uint64_t    key_id;
	int         result_size = VARHDRSZ + crypto_shorthash_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_shorthash_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_shorthash (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
