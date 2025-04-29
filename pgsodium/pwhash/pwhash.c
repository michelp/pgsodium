/* doctest/pwhash
-- # Password Hashing
--
-- Secret keys used to encrypt or sign confidential data have to be
-- chosen from a very large keyspace.
--
-- However, passwords are usually short, human-generated strings, making
-- dictionary attacks practical.
--
-- Password hashing functions derive a secret key of any size from a
-- password and salt.
--
--   - The generated key has the size defined by the application, no
--     matter what the password length is.
--
--   - The same password hashed with the same parameters will always
--     produce the same output.
--
--   - The same password hashed with different salts will produce
--     different outputs.
--
--   - The function deriving a key from a password and salt is CPU
--     intensive and intentionally requires a fair amount of
--     memory. Therefore, it mitigates brute-force attacks by requiring a
--     significant effort to verify each password.
--
-- Common use cases:
--
--   - Password storage, or rather storing what it takes to verify a
--     password without having to store the actual password.
--
--   - Deriving a secret key from a password; for example, for disk
--     encryption.
--
-- Sodium's high-level crypto_pwhash_* API currently leverages the
-- Argon2id function on all platforms. This can change at any point in
-- time, but it is guaranteed that a given version of libsodium can
-- verify all hashes produced by all previous versions from any
-- platform. Applications don't have to worry about backward
-- compatibility.

select pgsodium.crypto_pwhash_saltgen() salt \gset

select pgsodium.crypto_pwhash('Correct Horse Battery Staple', :'salt');

select pgsodium.crypto_pwhash_str('Correct Horse Battery Staple') hash \gset

select pgsodium.crypto_pwhash_str_verify((:'hash')::bytea, 'Correct Horse Battery Staple');

 */

#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_pwhash);
Datum
pgsodium_crypto_pwhash (PG_FUNCTION_ARGS)
{
	bytea      *data;
	bytea      *result;
	bytea      *salt;
	int         result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: data cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: salt cannot be NULL");

	data = PG_GETARG_BYTEA_PP (0);
	salt = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (salt) != crypto_pwhash_SALTBYTES,
		"%s: invalid salt");
	ERRORIF (VARSIZE_ANY_EXHDR (data) < crypto_pwhash_PASSWD_MIN
		|| VARSIZE_ANY_EXHDR (data) > crypto_pwhash_PASSWD_MAX,
		"%s: invalid password");
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_pwhash (
		PGSODIUM_UCHARDATA (result),
		crypto_box_SEEDBYTES,
		VARDATA_ANY (data),
		VARSIZE_ANY_EXHDR (data),
		PGSODIUM_UCHARDATA_ANY (salt),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT);
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}
