#include "pgsodium.h"

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
