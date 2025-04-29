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
