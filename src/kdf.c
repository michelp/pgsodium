#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kdf_keygen);
Datum
pgsodium_crypto_kdf_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_kdf_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kdf_derive_from_key);
Datum
pgsodium_crypto_kdf_derive_from_key (PG_FUNCTION_ARGS)
{
	size_t      subkey_size;
	size_t      result_size;
	unsigned long long subkey_id;
	bytea      *context;
	bytea      *primary_key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: subkey size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: subkey id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: subkey context cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: primary key cannot be NULL");

	subkey_size = PG_GETARG_UINT32 (0);
	result_size = VARHDRSZ + subkey_size;
	subkey_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	primary_key = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (primary_key) != crypto_kdf_KEYBYTES,
		"%s: invalid derivation key");
	ERRORIF (subkey_size < crypto_kdf_BYTES_MIN ||
		subkey_size > crypto_kdf_BYTES_MAX, "%s: invalid key size requested");
	ERRORIF (VARSIZE_ANY_EXHDR (context) != 8, "%s: context must be 8 bytes");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_derive_from_key (
		PGSODIUM_UCHARDATA (result),
		subkey_size,
		subkey_id,
		(const char *) VARDATA_ANY (context),
		PGSODIUM_UCHARDATA_ANY (primary_key));
	PG_RETURN_BYTEA_P (result);
}
