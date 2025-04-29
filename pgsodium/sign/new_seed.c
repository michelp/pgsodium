#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_new_seed);
Datum
pgsodium_crypto_sign_new_seed (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_sign_SEEDBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_sign_SEEDBYTES);
	PG_RETURN_BYTEA_P (result);
}
