#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_pwhash_saltgen);
Datum
pgsodium_crypto_pwhash_saltgen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_pwhash_SALTBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_pwhash_SALTBYTES);
	PG_RETURN_BYTEA_P (result);
}
