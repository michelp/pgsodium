#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_hash_sha256);
Datum
pgsodium_crypto_hash_sha256(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_hash_sha256_BYTES;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_hash_sha256(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_hash_sha512);
Datum
pgsodium_crypto_hash_sha512(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_hash_sha512_BYTES;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_hash_sha512(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message));
	PG_RETURN_BYTEA_P(result);
}
