#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_saltgen);
Datum
pgsodium_crypto_pwhash_saltgen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_pwhash_SALTBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_pwhash_SALTBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash);
Datum
pgsodium_crypto_pwhash(PG_FUNCTION_ARGS)
{
	bytea* data;
	bytea* result;
	bytea* salt;
	int result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	int success;
	data = PG_GETARG_BYTEA_P(0);
	salt = PG_GETARG_BYTEA_P(1);
	ERRORIF(VARSIZE_ANY_EXHDR(salt) != crypto_pwhash_SALTBYTES, "invalid salt");
	ERRORIF(VARSIZE_ANY_EXHDR(data) < crypto_pwhash_PASSWD_MIN ||
			VARSIZE_ANY_EXHDR(data) > crypto_pwhash_PASSWD_MAX,
			"invalid password");
	result = _pgsodium_zalloc_bytea(result_size);
	success = crypto_pwhash(
		PGSODIUM_UCHARDATA(result),
		crypto_box_SEEDBYTES,
		VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		PGSODIUM_UCHARDATA(salt),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT);
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str);
Datum
pgsodium_crypto_pwhash_str(PG_FUNCTION_ARGS)
{
	int success;
	bytea* password = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(crypto_pwhash_STRBYTES + VARHDRSZ);
	success = crypto_pwhash_str(
		VARDATA(result),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE);
	ERRORIF(success != 0, "out of memory in pwhash_str");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str_verify);
Datum
pgsodium_crypto_pwhash_str_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hashed_password = PG_GETARG_BYTEA_P(0);
	bytea* password = PG_GETARG_BYTEA_P(1);
	success = crypto_pwhash_str_verify(
		VARDATA(hashed_password),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password));
	PG_RETURN_BOOL(success == 0);
}
