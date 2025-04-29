#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_open);
Datum
pgsodium_crypto_secretbox_open (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *nonce;
	bytea      *key;
	size_t      message_size;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_P (0);
	nonce = PG_GETARG_BYTEA_P (1);
	key = PG_GETARG_BYTEA_P (2);

	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_secretbox_MACBYTES,
		"%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_secretbox_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_secretbox_KEYBYTES,
		"%s: invalid key");

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
