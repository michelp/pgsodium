#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_xor_ic);
Datum
pgsodium_crypto_stream_xchacha20_xor_ic (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *nonce;
	uint64_t    ic;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: ic cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	ic = PG_GETARG_INT64 (2);
	key = PG_GETARG_BYTEA_PP (3);
	result_size = VARSIZE_ANY_EXHDR (data);
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_stream_xchacha20_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_stream_xchacha20_KEYBYTES,
		"%s: invalid key");
	crypto_stream_xchacha20_xor_ic (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (data),
		result_size, PGSODIUM_UCHARDATA_ANY (nonce), ic, PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
