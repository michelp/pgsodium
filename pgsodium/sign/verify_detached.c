#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_verify_detached);
Datum
pgsodium_crypto_sign_verify_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *sig;
	bytea      *message;
	bytea      *publickey;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: publickey cannot be NULL");

	sig       = PG_GETARG_BYTEA_PP (0);
	message   = PG_GETARG_BYTEA_PP (1);
	publickey = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	success = crypto_sign_verify_detached (
		PGSODIUM_UCHARDATA_ANY (sig),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (publickey));
	PG_RETURN_BOOL (success == 0);
}
