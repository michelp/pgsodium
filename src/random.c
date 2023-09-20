#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_random);
Datum
pgsodium_randombytes_random (PG_FUNCTION_ARGS)
{
	PG_RETURN_UINT32 (randombytes_random ());
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_uniform);
Datum
pgsodium_randombytes_uniform (PG_FUNCTION_ARGS)
{
	uint32_t    upper_bound;
	ERRORIF (PG_ARGISNULL (0), "%s: upper bound cannot be NULL");
	upper_bound = PG_GETARG_UINT32 (0);
	PG_RETURN_UINT32 (randombytes_uniform (upper_bound));
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_buf);
Datum
pgsodium_randombytes_buf (PG_FUNCTION_ARGS)
{
	size_t      size;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: buffer size cannot be NULL");
	size = PG_GETARG_UINT32 (0);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	randombytes_buf (VARDATA (result), size);
	PG_RETURN_BYTEA_P (result);
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_randombytes_new_seed);
Datum
pgsodium_randombytes_new_seed (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + randombytes_SEEDBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), randombytes_SEEDBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_buf_deterministic);
Datum
pgsodium_randombytes_buf_deterministic (PG_FUNCTION_ARGS)
{
	size_t      size;
	bytea      *seed;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: buffer size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: seed cannot be NULL");

	size = PG_GETARG_UINT32 (0);
	seed = PG_GETARG_BYTEA_P (1);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	randombytes_buf_deterministic (VARDATA (result), size,
		PGSODIUM_UCHARDATA (seed));
	PG_RETURN_BYTEA_P (result);
}
