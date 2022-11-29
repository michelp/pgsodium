#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_keygen);
Datum
pgsodium_crypto_secretbox_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_secretbox_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_secretbox_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_noncegen);
Datum
pgsodium_crypto_secretbox_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size = VARHDRSZ + crypto_secretbox_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox);
Datum
pgsodium_crypto_secretbox (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *nonce;
	bytea      *key;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_P (0);
	nonce = PG_GETARG_BYTEA_P (1);
	key = PG_GETARG_BYTEA_P (2);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) != crypto_secretbox_NONCEBYTES,
		"%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_secretbox_KEYBYTES,
		"%s: invalid key");
	result_size = crypto_secretbox_MACBYTES + VARSIZE_ANY (message);
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_secretbox_easy (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_secretbox_by_id);
Datum
pgsodium_crypto_secretbox_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *nonce;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
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
	result_size = crypto_secretbox_MACBYTES + VARSIZE_ANY (message);
	result = _pgsodium_zalloc_bytea (result_size);

	crypto_secretbox_easy (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

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
