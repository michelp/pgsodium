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

PG_FUNCTION_INFO_V1 (pgsodium_crypto_pwhash);
Datum
pgsodium_crypto_pwhash (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *salt;
	int         result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: salt cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	salt = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (salt) != crypto_pwhash_SALTBYTES,
		"%s: invalid salt");
	ERRORIF (VARSIZE_ANY_EXHDR (data) < crypto_pwhash_PASSWD_MIN
		|| VARSIZE_ANY_EXHDR (data) > crypto_pwhash_PASSWD_MAX,
		"%s: invalid password");
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_pwhash (
		PGSODIUM_UCHARDATA (result),
		crypto_box_SEEDBYTES,
		VARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA_ANY (salt),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT);
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_pwhash_str);
Datum
pgsodium_crypto_pwhash_str (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *password;
	bytea      *result =
		_pgsodium_zalloc_bytea (crypto_pwhash_STRBYTES + VARHDRSZ);

	ERRORIF (PG_ARGISNULL (0), "%s: password cannot be NULL");

	password = PG_GETARG_BYTEA_PP (0);
	success =
		crypto_pwhash_str (
			VARDATA (result),
			VARDATA_ANY (password),
			VARSIZE_ANY_EXHDR (password),
			crypto_pwhash_OPSLIMIT_MODERATE,
			crypto_pwhash_MEMLIMIT_MODERATE);
	ERRORIF (success != 0, "%s: out of memory in pwhash_str");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_pwhash_str_verify);
Datum
pgsodium_crypto_pwhash_str_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hashed_password;
	bytea      *password;

	ERRORIF (PG_ARGISNULL (0), "%s: hashed password cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: password cannot be NULL");

	hashed_password = PG_GETARG_BYTEA_PP (0);
	password = PG_GETARG_BYTEA_PP (1);

	success = crypto_pwhash_str_verify (
		VARDATA_ANY (hashed_password),
		VARDATA_ANY (password),
		VARSIZE_ANY_EXHDR (password));
	PG_RETURN_BOOL (success == 0);
}
