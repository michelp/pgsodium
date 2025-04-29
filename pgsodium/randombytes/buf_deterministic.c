#include "pgsodium.h"

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
