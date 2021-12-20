
#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_keygen);
Datum
pgsodium_crypto_stream_xchacha20_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_stream_xchacha20_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_stream_xchacha20_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_noncegen);
Datum
pgsodium_crypto_stream_xchacha20_noncegen(PG_FUNCTION_ARGS)
{
	int result_size = VARHDRSZ + crypto_stream_xchacha20_NONCEBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_stream_xchacha20_NONCEBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20);
Datum
pgsodium_crypto_stream_xchacha20(PG_FUNCTION_ARGS)
{
}

PG_FUNCTION_INFO_V1_xor(pgsodium_crypto_stream_xchacha20);
Datum
pgsodium_crypto_stream_xchacha20_xor(PG_FUNCTION_ARGS)
{
}

