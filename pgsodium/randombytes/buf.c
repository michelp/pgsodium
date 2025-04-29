#include "pgsodium.h"

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
