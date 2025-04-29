#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kdf_keygen);
Datum
pgsodium_crypto_kdf_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_kdf_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}
