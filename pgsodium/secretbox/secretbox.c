/* doctest/secretbox
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Secret Key Cryptography

select pgsodium.crypto_secretbox_keygen() key \gset

select pgsodium.crypto_secretbox_noncegen() nonce \gset

select pgsodium.crypto_secretbox('bob is your uncle', :'nonce', :'key') secretbox \gset

select pgsodium.crypto_secretbox_open(:'secretbox', :'nonce', :'key');

 */
#include "pgsodium.h"

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

