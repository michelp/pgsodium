#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_verify_by_id);
Datum
pgsodium_crypto_auth_hmacsha256_verify_by_id (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha256_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha256_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha256_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BOOL (success == 0);
}
