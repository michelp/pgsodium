/* doctest/random
-- # Generating Random Data
--
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
--
-- The library provides a set of functions to generate unpredictable data, suitable for creating secret keys.
--
-- - On Windows systems, the RtlGenRandom() function is used.
-- - On OpenBSD and Bitrig, the arc4random() function is used.
-- - On recent FreeBSD and Linux kernels, the getrandom system call is used.
-- - On other Unices, the /dev/urandom device is used.

-- ## `randombytes_random()`
--
-- Returns a random 32-bit signed integer.

select pgsodium.randombytes_random() from generate_series(0, 5);

-- ## `randombytes_uniform(upper_bound interger)`
--
-- Returns a uniformally distributed random number between zero and the upper bound argument.

select pgsodium.randombytes_uniform(10) + 3 from generate_series(0, 5);

-- ## `randombytes_buf(buffer_size integer)`
--
-- Returns a random buffer of bytes the size of the argument.

select encode(pgsodium.randombytes_buf(10), 'hex') from generate_series(0, 5);

*/

#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_random);
Datum
pgsodium_randombytes_random (PG_FUNCTION_ARGS)
{
	PG_RETURN_UINT32 (randombytes_random ());
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_uniform);
Datum
pgsodium_randombytes_uniform (PG_FUNCTION_ARGS)
{
	uint32_t    upper_bound;
	ERRORIF (PG_ARGISNULL (0), "%s: upper bound cannot be NULL");
	upper_bound = PG_GETARG_UINT32 (0);
	PG_RETURN_UINT32 (randombytes_uniform (upper_bound));
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_buf);
Datum
pgsodium_randombytes_buf (PG_FUNCTION_ARGS)
{
	size_t      size;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: buffer size cannot be NULL");
	size = PG_GETARG_UINT32 (0);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	randombytes_buf (VARDATA (result), size);
	PG_RETURN_BYTEA_P (result);
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_randombytes_new_seed);
Datum
pgsodium_randombytes_new_seed (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + randombytes_SEEDBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), randombytes_SEEDBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_randombytes_buf_deterministic);
Datum
pgsodium_randombytes_buf_deterministic (PG_FUNCTION_ARGS)
{
	size_t      size;
	bytea      *seed;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: buffer size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: seed cannot be NULL");

	size = PG_GETARG_UINT32 (0);
	seed = PG_GETARG_BYTEA_P (1);
	result_size = VARHDRSZ + size;
	result = _pgsodium_zalloc_bytea (result_size);

	randombytes_buf_deterministic (VARDATA (result), size,
		PGSODIUM_UCHARDATA (seed));
	PG_RETURN_BYTEA_P (result);
}
