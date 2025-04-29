#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_open_by_id);
Datum
pgsodium_crypto_secretbox_open_by_id (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *nonce;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	size_t      message_size;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_P (0);
	nonce = PG_GETARG_BYTEA_P (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_P (3);
	key = pgsodium_derive_helper (key_id, crypto_secretbox_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_secretbox_MACBYTES,
		"%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_secretbox_NONCEBYTES,
		"%s: invalid nonce");

	message_size = VARSIZE_ANY_EXHDR (message) - crypto_secretbox_MACBYTES;
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea (result_size);

	success = crypto_secretbox_open_easy (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
