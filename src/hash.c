/* doctest/hash
-- # Hashing Data
--
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
--
-- libsodium provides functions for "generic" and "short" hashing.
--
-- Generic hashing is suitable for cryptographic purposes using the BLAKE2b algorithm.

select pgsodium.crypto_generichash('this is a message');

select pgsodium.crypto_generichash_keygen() generickey \gset

select pgsodium.crypto_generichash('this is a message'::bytea, :'generickey'::bytea);

-- ## Short Hashing
--
-- Many applications and programming language implementations were
-- recently found to be vulnerable to denial-of-service (DoS) attacks
-- when a hash function with weak security guarantees, such as
-- MurmurHash3, was used to construct a hash table.
--
-- To address this, Sodium provides the crypto_shorthash() function,
-- which outputs short but unpredictable (without knowing the secret key)
-- values suitable for picking a list in a hash table for a given key.
--
-- This function is optimized for short inputs.
--
-- The output of this function is only 64 bits. Therefore, it should not
-- be considered collision-resistant.
--
-- Use cases:
-- - Hash tables
-- - Probabilistic data structures, such as Bloom filters
-- - Integrity checking in interactive protocols

select pgsodium.crypto_shorthash_keygen() shortkey \gset
select pgsodium.crypto_shorthash('this is a message'::bytea, :'shortkey'::bytea);

*/

#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_generichash_keygen);
Datum
pgsodium_crypto_generichash_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_generichash_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_generichash_KEYBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_generichash);
Datum
pgsodium_crypto_generichash (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *keyarg;
	unsigned char *key = NULL;
	size_t      keylen = 0;
	size_t      result_size;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		keyarg = PG_GETARG_BYTEA_PP (1);
		key = PGSODIUM_UCHARDATA_ANY (keyarg);
		keylen = VARSIZE_ANY_EXHDR (keyarg);
		ERRORIF (keylen < crypto_generichash_KEYBYTES_MIN ||
			keylen > crypto_generichash_KEYBYTES_MAX, "%s: invalid key");
	}
	result_size = VARHDRSZ + crypto_generichash_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_generichash (
		PGSODIUM_UCHARDATA (result),
		crypto_generichash_BYTES,
		PGSODIUM_UCHARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		key,
		keylen);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_shorthash_keygen);
Datum
pgsodium_crypto_shorthash_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_shorthash_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_shorthash_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_shorthash);
Datum
pgsodium_crypto_shorthash (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *key;
	int         result_size = VARHDRSZ + crypto_shorthash_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_shorthash_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_shorthash (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_generichash_by_id);
Datum
pgsodium_crypto_generichash_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *keyarg;
	bytea      *context;
	unsigned char *key = NULL;
	size_t      keylen = 0;
	size_t      result_size;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		unsigned long long key_id = PG_GETARG_INT64 (1);
		ERRORIF (PG_ARGISNULL (2), "%s: key context be NULL");
		context = PG_GETARG_BYTEA_PP (2);
		keyarg =
			pgsodium_derive_helper (key_id, crypto_generichash_KEYBYTES,
			context);
		key = PGSODIUM_UCHARDATA_ANY (keyarg);
		keylen = VARSIZE_ANY_EXHDR (keyarg);
		ERRORIF (keylen < crypto_generichash_KEYBYTES_MIN ||
			keylen > crypto_generichash_KEYBYTES_MAX, "%s: invalid key");
	}
	result_size = VARHDRSZ + crypto_generichash_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_generichash (
		PGSODIUM_UCHARDATA (result),
		crypto_generichash_BYTES,
		PGSODIUM_UCHARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		key,
		keylen);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_shorthash_by_id);
Datum
pgsodium_crypto_shorthash_by_id (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *key;
	bytea      *context;
	uint64_t    key_id;
	int         result_size = VARHDRSZ + crypto_shorthash_BYTES;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	key = pgsodium_derive_helper (key_id, crypto_shorthash_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_shorthash (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
