#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_public);
Datum
pgsodium_crypto_signcrypt_verify_public (PG_FUNCTION_ARGS)
{
	bytea      *signature;
	bytea      *sender;
	bytea      *recipient;
	bytea      *associated;
	bytea      *sender_pk;
	bytea      *ciphertext;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: sender cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: recipient cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: associated cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: sender publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (5), "%s: ciphertext cannot be NULL");

	signature = PG_GETARG_BYTEA_PP (0);
	sender = PG_GETARG_BYTEA_PP (1);
	recipient = PG_GETARG_BYTEA_PP (2);
	associated = PG_GETARG_BYTEA_PP (3);
	sender_pk = PG_GETARG_BYTEA_PP (4);
	ciphertext = PG_GETARG_BYTEA_PP (5);

	success =
		crypto_signcrypt_tbsr_verify_public (
			PGSODIUM_UCHARDATA_ANY (signature),
			PGSODIUM_UCHARDATA_ANY (sender),
			VARSIZE_ANY_EXHDR (sender),
			PGSODIUM_UCHARDATA_ANY (recipient),
			VARSIZE_ANY_EXHDR (recipient),
			PGSODIUM_UCHARDATA_ANY (associated),
			VARSIZE_ANY_EXHDR (associated),
			PGSODIUM_UCHARDATA_ANY (sender_pk),
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_public failed");
	PG_RETURN_BOOL (success == 0);
}
