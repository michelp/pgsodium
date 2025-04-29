#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20);
Datum
pgsodium_crypto_stream_xchacha20 (PG_FUNCTION_ARGS)
{
	size_t      size;
	bytea      *nonce;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	size = PG_GETARG_INT64 (0);
	nonce = PG_GETARG_BYTEA_P (1);
	key = PG_GETARG_BYTEA_P (2);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_stream_xchacha20_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_stream_xchacha20_KEYBYTES,
		"%s: invalid key");

	crypto_stream_xchacha20 (PGSODIUM_UCHARDATA (result),
		result_size, PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}
