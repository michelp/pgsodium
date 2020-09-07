#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512_keygen);
Datum
pgsodium_crypto_auth_hmacsha512_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha512_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha512_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512);
Datum
pgsodium_crypto_auth_hmacsha512(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha512_KEYBYTES, "invalid key");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha512(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512_verify);
Datum
pgsodium_crypto_auth_hmacsha512_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hash = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(hash) != crypto_auth_hmacsha512_BYTES, "invalid hash");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha512_KEYBYTES, "invalid key");
	success = crypto_auth_hmacsha512_verify(
		PGSODIUM_UCHARDATA(hash),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256_keygen);
Datum
pgsodium_crypto_auth_hmacsha256_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha256_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha256_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256);
Datum
pgsodium_crypto_auth_hmacsha256(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha256_KEYBYTES, "invalid key");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha256(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256_verify);
Datum
pgsodium_crypto_auth_hmacsha256_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hash = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(hash) != crypto_auth_hmacsha256_BYTES, "invalid hash");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha256_KEYBYTES, "invalid key");
	success = crypto_auth_hmacsha256_verify(
		PGSODIUM_UCHARDATA(hash),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BOOL(success == 0);
}
