#include "pgsodium.h"
#include <sodium.h>
PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pgsodium_randombytes_random);
Datum
pgsodium_randombytes_random(PG_FUNCTION_ARGS)
{
	PG_RETURN_UINT32(randombytes_random());
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_uniform);
Datum
pgsodium_randombytes_uniform(PG_FUNCTION_ARGS)
{
	uint32_t upper_bound = PG_GETARG_UINT32(0);
	PG_RETURN_UINT32(randombytes_uniform(upper_bound));
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_buf);
Datum
pgsodium_randombytes_buf(PG_FUNCTION_ARGS)
{
	size_t size = PG_GETARG_UINT32(0);
	bytea *ret = (bytea *) palloc(VARHDRSZ + size);
	SET_VARSIZE(ret, VARHDRSZ + size);
	randombytes_buf(VARDATA(ret), size);
	PG_RETURN_BYTEA_P(ret);
}

void _PG_init(void) {
	if (sodium_init() == -1) {
		elog(ERROR, "_PG_init: sodium_init() failed cannot initialize pgsodium");
		return;
	}
}
