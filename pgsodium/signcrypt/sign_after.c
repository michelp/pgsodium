#include "pgsodium.h"

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_sign_after);
Datum
pgsodium_crypto_signcrypt_sign_after (PG_FUNCTION_ARGS)
{
	bytea      *state;
	bytea      *sender_sk;
	bytea      *ciphertext;
	bytea      *signature =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SIGNBYTES + VARHDRSZ);
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: sender secretkey cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: ciphertext cannot be NULL");

	state = PG_GETARG_BYTEA_PP (0);
	sender_sk = PG_GETARG_BYTEA_PP (1);
	ciphertext = PG_GETARG_BYTEA_PP (2);

	success = crypto_signcrypt_tbsbr_sign_after (
		PGSODIUM_UCHARDATA_ANY (state),
		PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA_ANY (sender_sk),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext));
	ERRORIF (success != 0, "%s: sign_after failed");
	PG_RETURN_BYTEA_P (signature);
}
