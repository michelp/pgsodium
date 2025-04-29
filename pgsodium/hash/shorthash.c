#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_shorthash);
Datum
pgsodium_crypto_shorthash (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *key;
	int         result_size = VARHDRSZ + crypto_shorthash_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_shorthash_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_shorthash (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}
