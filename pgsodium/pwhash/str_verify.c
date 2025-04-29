#include "pgsodium.h"

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
