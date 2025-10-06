/* doctest/hmac
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Hash-based Message Authentication Codes
--
--
-- [https://en.wikipedia.org/wiki/HMAC]
--
-- In cryptography, an HMAC (sometimes expanded as either keyed-hash
-- message authentication code or hash-based message authentication code)
-- is a specific type of message authentication code (MAC) involving a
-- cryptographic hash function and a secret cryptographic key. As with
-- any MAC, it may be used to simultaneously verify both the data
-- integrity and authenticity of a message.
--
-- [C API Documentation](https://doc.libsodium.org/advanced/hmac-sha2)
--
-- pgsodium provides hmacsha512 and hmacsha256, only 512-bit examples are
-- provided below, the 256-bit API is identical but using names like
-- `crypto_auth_hmacsha256_*`.
--
select pgsodium.crypto_auth_hmacsha512_keygen() hmackey \gset

select pgsodium.crypto_auth_hmacsha512('this is authentic'::bytea, :'hmackey'::bytea) signature \gset

select pgsodium.crypto_auth_hmacsha512_verify(:'signature'::bytea, 'this is authentic'::bytea, :'hmackey'::bytea);

 */

#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_keygen);
Datum
pgsodium_crypto_auth_hmacsha512_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512);
Datum
pgsodium_crypto_auth_hmacsha512 (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_by_id);
Datum
pgsodium_crypto_auth_hmacsha512_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha512_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha512 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_verify);
Datum
pgsodium_crypto_auth_hmacsha512_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha512_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha512_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha512_verify_by_id);
Datum
pgsodium_crypto_auth_hmacsha512_verify_by_id (PG_FUNCTION_ARGS)
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
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha512_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha512_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha512_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha512_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_keygen);
Datum
pgsodium_crypto_auth_hmacsha256_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256);
Datum
pgsodium_crypto_auth_hmacsha256 (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *key;
	bytea      *result;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256 (
		PGSODIUM_UCHARDATA_ANY (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_verify);
Datum
pgsodium_crypto_auth_hmacsha256_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *hash;
	bytea      *message;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: hash cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	hash = PG_GETARG_BYTEA_PP (0);
	message = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (hash) != crypto_auth_hmacsha256_BYTES,
		"%s: invalid hash");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	success = crypto_auth_hmacsha256_verify (
		PGSODIUM_UCHARDATA_ANY (hash),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_auth_hmacsha256_by_id);
Datum
pgsodium_crypto_auth_hmacsha256_by_id (PG_FUNCTION_ARGS)
{
	bytea      *result;
	size_t      result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;
	bytea      *message;
	uint64_t    key_id;
	bytea      *context;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_auth_hmacsha256_KEYBYTES, context);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_auth_hmacsha256_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_auth_hmacsha256 (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

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
