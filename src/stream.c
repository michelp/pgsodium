
#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_keygen);
Datum
pgsodium_crypto_stream_xchacha20_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_stream_xchacha20_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_stream_xchacha20_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_noncegen);
Datum
pgsodium_crypto_stream_xchacha20_noncegen (PG_FUNCTION_ARGS)
{
	uint64_t    result_size = VARHDRSZ + crypto_stream_xchacha20_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_stream_xchacha20_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}

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

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_xor);
Datum
pgsodium_crypto_stream_xchacha20_xor (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *nonce;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);
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

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_by_id);
Datum
pgsodium_crypto_stream_xchacha20_by_id (PG_FUNCTION_ARGS)
{
	size_t      size;
	bytea      *nonce;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	size = PG_GETARG_INT64 (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	key = pgsodium_derive_helper (key_id, crypto_stream_xchacha20_KEYBYTES,	context);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_stream_xchacha20_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_stream_xchacha20_KEYBYTES,
		"%s: invalid key");

	crypto_stream_xchacha20 (PGSODIUM_UCHARDATA (result),
		result_size, PGSODIUM_UCHARDATA_ANY (nonce), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

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

PG_FUNCTION_INFO_V1 (pgsodium_crypto_stream_xchacha20_xor_ic_by_id);
Datum
pgsodium_crypto_stream_xchacha20_xor_ic_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *nonce;
	uint64_t    ic;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;
	uint64_t    result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: ic cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key id context cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: key context cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	ic = PG_GETARG_INT64 (2);
	key_id = PG_GETARG_INT64 (3);
	context = PG_GETARG_BYTEA_PP (4);

	key = pgsodium_derive_helper (key_id, crypto_stream_xchacha20_KEYBYTES,	context);
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
