#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_randombytes_new_seed);
Datum
pgsodium_randombytes_new_seed (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + randombytes_SEEDBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), randombytes_SEEDBYTES);
	PG_RETURN_BYTEA_P (result);
}
