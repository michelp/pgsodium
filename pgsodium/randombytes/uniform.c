#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_uniform);
Datum
pgsodium_randombytes_uniform (PG_FUNCTION_ARGS)
{
	uint32_t    upper_bound;
	ERRORIF (PG_ARGISNULL (0), "%s: upper bound cannot be NULL");
	upper_bound = PG_GETARG_UINT32 (0);
	PG_RETURN_UINT32 (randombytes_uniform (upper_bound));
}
