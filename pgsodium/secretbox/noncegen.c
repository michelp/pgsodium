#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_noncegen);
Datum
pgsodium_crypto_secretbox_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size = VARHDRSZ + crypto_secretbox_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}
