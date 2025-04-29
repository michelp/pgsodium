#include "pgsodium.h"

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
