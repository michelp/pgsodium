#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_keygen);
Datum
pgsodium_crypto_auth_hmacsha512_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512);
Datum
pgsodium_crypto_auth_hmacsha512 (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_by_id);
Datum
pgsodium_crypto_auth_hmacsha512_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha512_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_verify);
Datum
pgsodium_crypto_auth_hmacsha512_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha512_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha512_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_verify_by_id);
Datum
pgsodium_crypto_auth_hmacsha512_verify_by_id (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha512_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha512_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha512_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_keygen);
Datum
pgsodium_crypto_auth_hmacsha256_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256);
Datum
pgsodium_crypto_auth_hmacsha256 (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	bytea      *result;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256 (
		PGSODIUM_UCHARDATA_ANY (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_verify);
Datum
pgsodium_crypto_auth_hmacsha256_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha256_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha256_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_by_id);
Datum
pgsodium_crypto_auth_hmacsha256_by_id (PG_FUNCTION_ARGS)
{
	bytea      *result;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha256_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_verify_by_id);
Datum
pgsodium_crypto_auth_hmacsha256_verify_by_id (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha256_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha256_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha256_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BOOL (success == 0);
}
