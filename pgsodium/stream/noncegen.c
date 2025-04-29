#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_noncegen);
Datum
pgsodium_crypto_stream_xchacha20_noncegen (PG_FUNCTION_ARGS)
{
	uint64_t    result_size = VARHDRSZ + crypto_stream_xchacha20_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_stream_xchacha20_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}
