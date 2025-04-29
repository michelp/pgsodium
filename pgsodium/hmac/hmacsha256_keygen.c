#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_keygen);
Datum
pgsodium_crypto_auth_hmacsha256_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}
