#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_noncegen);
Datum
pgsodium_crypto_aead_ietf_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size =
		VARHDRSZ + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result),
					 crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
	PG_RETURN_BYTEA_P (result);
}
