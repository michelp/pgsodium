#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_keygen);
Datum
pgsodium_crypto_aead_ietf_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size =
		VARHDRSZ + crypto_aead_chacha20poly1305_IETF_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_aead_chacha20poly1305_ietf_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}
