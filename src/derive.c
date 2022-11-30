#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_derive);
Datum
pgsodium_derive (PG_FUNCTION_ARGS)
{
	unsigned long long subkey_id;
	size_t      subkey_size;
	bytea      *context;

	ERRORIF (PG_ARGISNULL (0), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key size cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	subkey_id = PG_GETARG_INT64 (0);
	subkey_size = PG_GETARG_UINT32 (1);
	context = PG_GETARG_BYTEA_PP (2);

	PG_RETURN_BYTEA_P (pgsodium_derive_helper (subkey_id, subkey_size,
			context));
}
