#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth);
Datum
pgsodium_crypto_auth (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	int         result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_KEYBYTES,
		"%s: invalid key");
	result_size = VARHDRSZ + crypto_auth_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_by_id);
Datum
pgsodium_crypto_auth_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	int         result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);

	key = pgsodium_derive_helper (key_id, crypto_auth_KEYBYTES, context);
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_KEYBYTES,
		"%s: invalid key");
	result_size = VARHDRSZ + crypto_auth_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_verify);
Datum
pgsodium_crypto_auth_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *mac;
	bytea      *message;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	mac = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (mac) != crypto_auth_BYTES, "%s: invalid mac");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_KEYBYTES,
		"%s: invalid key");
	success =
		crypto_auth_verify (
			PGSODIUM_UCHARDATA_ANY (mac),
			PGSODIUM_UCHARDATA_ANY (message),
			VARSIZE_ANY_EXHDR (message),
			PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_verify_by_id);
Datum
pgsodium_crypto_auth_verify_by_id (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *mac;
	bytea      *message;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	mac = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);

	key = pgsodium_derive_helper (key_id, crypto_secretbox_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (mac) != crypto_auth_BYTES, "%s: invalid mac");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_KEYBYTES,
		"%s: invalid key");
	success =
		crypto_auth_verify (
			PGSODIUM_UCHARDATA_ANY (mac),
			PGSODIUM_UCHARDATA_ANY (message),
			VARSIZE_ANY_EXHDR (message),
			PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_keygen);
Datum
pgsodium_crypto_auth_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_secretbox_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}
