#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_kdf_keygen);
Datum
pgsodium_crypto_kdf_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_kdf_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_kdf_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kdf_derive_from_key);
Datum
pgsodium_crypto_kdf_derive_from_key(PG_FUNCTION_ARGS)
{
	size_t subkey_size = PG_GETARG_UINT32(0);
	size_t result_size = VARHDRSZ + subkey_size;
	unsigned long long subkey_id = PG_GETARG_INT64(1);
	bytea* context = PG_GETARG_BYTEA_P(2);
	bytea* primary_key = PG_GETARG_BYTEA_P(3);
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(primary_key) != crypto_kdf_KEYBYTES,
			"invalid derivation key");
	ERRORIF(subkey_size < crypto_kdf_BYTES_MIN || subkey_size > crypto_kdf_BYTES_MAX,
			"crypto_kdf_derive_from_key: invalid key size requested");
	ERRORIF(VARSIZE_ANY_EXHDR(context) != 8,
			"crypto_kdf_derive_from_key: context must be 8 bytes");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_kdf_derive_from_key(
		PGSODIUM_UCHARDATA(result),
		subkey_size,
		subkey_id,
		(const char*)VARDATA(context),
		PGSODIUM_UCHARDATA(primary_key));
	PG_RETURN_BYTEA_P(result);
}

