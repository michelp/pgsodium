#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_xor_by_id);
Datum
pgsodium_crypto_stream_xchacha20_xor_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *nonce;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	key = pgsodium_derive_helper (key_id, crypto_stream_xchacha20_KEYBYTES,	context);
	result_size = VARSIZE_ANY_EXHDR (data);
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_stream_xchacha20_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_stream_xchacha20_KEYBYTES,
		"%s: invalid key");

	crypto_stream_xchacha20_xor (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (data),
		result_size, PGSODIUM_UCHARDATA_ANY (nonce), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
