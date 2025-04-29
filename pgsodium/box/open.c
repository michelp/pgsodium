#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_box_open);
Datum
pgsodium_crypto_box_open (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *nonce;
	bytea      *publickey;
	bytea      *secretkey;
	size_t      message_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	nonce = PG_GETARG_BYTEA_PP (1);
	publickey = PG_GETARG_BYTEA_PP (2);
	secretkey = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_box_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_box_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_box_SECRETKEYBYTES,
		"%s: invalid secret key");
	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_box_MACBYTES,
		"%s: invalid message");

	message_size = VARSIZE_ANY (message) - crypto_box_MACBYTES;
	result = _pgsodium_zalloc_bytea (message_size);
	success = crypto_box_open_easy (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (nonce),
		PGSODIUM_UCHARDATA_ANY (publickey),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
