#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_generichash_by_id);
Datum
pgsodium_crypto_generichash_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *keyarg;
	bytea      *context;
	unsigned char *key = NULL;
	size_t      keylen = 0;
	size_t      result_size;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		unsigned long long key_id = PG_GETARG_INT64 (1);
		ERRORIF (PG_ARGISNULL (2), "%s: key context be NULL");
		context = PG_GETARG_BYTEA_PP (2);
		keyarg =
			pgsodium_derive_helper (key_id, crypto_generichash_KEYBYTES,
			context);
		key = PGSODIUM_UCHARDATA_ANY (keyarg);
		keylen = VARSIZE_ANY_EXHDR (keyarg);
		ERRORIF (keylen < crypto_generichash_KEYBYTES_MIN ||
			keylen > crypto_generichash_KEYBYTES_MAX, "%s: invalid key");
	}
	result_size = VARHDRSZ + crypto_generichash_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_generichash (
		PGSODIUM_UCHARDATA (result),
		crypto_generichash_BYTES,
		PGSODIUM_UCHARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		key,
		keylen);
	PG_RETURN_BYTEA_P (result);
}
