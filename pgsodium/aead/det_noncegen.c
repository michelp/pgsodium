#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_noncegen);
Datum
pgsodium_crypto_aead_det_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size = VARHDRSZ + crypto_aead_det_xchacha20_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_aead_det_xchacha20_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}
