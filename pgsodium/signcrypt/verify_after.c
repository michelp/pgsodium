#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_after);
Datum
pgsodium_crypto_signcrypt_verify_after (PG_FUNCTION_ARGS)
{
	bytea      *state;
	bytea      *signature;
	bytea      *sender_pk;
	bytea      *ciphertext;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: sender publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: ciphertext cannot be NULL");

	state = PG_GETARG_BYTEA_PP (0);
	signature = PG_GETARG_BYTEA_PP (1);
	sender_pk = PG_GETARG_BYTEA_PP (2);
	ciphertext = PG_GETARG_BYTEA_PP (3);

	success =
		crypto_signcrypt_tbsbr_verify_after (
			PGSODIUM_UCHARDATA_ANY (state),
			PGSODIUM_UCHARDATA_ANY (signature),
			PGSODIUM_UCHARDATA_ANY (sender_pk),
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_after failed");
	PG_RETURN_BOOL (success == 0);
}
