#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_box_noncegen);
Datum
pgsodium_crypto_box_noncegen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_box_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_box_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}
