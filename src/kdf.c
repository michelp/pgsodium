/* doctest/kdf
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
-- # Server Key Management
--
-- The core feature of pgsodium its its ability to manage encryption keys
-- for you, you so that you never reference a raw encryption key, but
-- instead you reference keys *by ID*.  A key id is a UUID that uniquely
-- identifies the key used.  An example of using Server Key Management
-- can be found in the section on [Transparent Column
-- Encryption](Transparent_Column_Encryption.md) and is most of the API
-- examples that can take key UUIDs are arguments.
--
-- ## Create a new Key
--
-- pgsodium can manage two types of keys, *derived* keys, and *external*
-- keys.  Derived keys use libsodium to
--
-- Server managed keys are created with the `pgsodium.create_key()`
-- function.  This function takes a few optional parameters:
--
-- - `key_type`: The type of key to create, the default is `aead-det`.
--   Can be one of:
--
--   - `aead-det`
--   - `aead-ietf`
--   - `hmacsha512`
--   - `hmacsha256`
--   - `auth`
--   - `secretbox`
--   - `secretstream`
--   - `shorthash`
--   - `generichash`
--   - `kdf`
--
-- - `name`: An optional *unique* name for the key.  The default is NULL
--   which makes an "anonymous" key.
--
-- - `derived_key`: An optional raw external key, for example an hmac key
--   from an external service.  pgsodium will store this key encrypted
--   with TCE.
--
-- - `derived_key_nonce`: An optional nonce for the raw key, if none is
--   provided a new random `aead-det` nonce will be generated using
--   `pgsodium.crypto_aead_det_noncegen()`.
--
-- - `parent_key`: If `raw_key` is not null, then this key id is used to
--   encrypt the raw key.  The default is to generate a new `aead-det`
--   key.
--
-- - `derived_context`
--
-- - `expires`
--
-- - `associated_data`
--
-- `pgsodium.create_key()` returns a new row in the `pgsodium.valid_key`
-- view.  For most purposes, you usually just need the new key's ID to
-- start using it.  For example, here's a new external shahmac256 key
-- being created and used to verify a payload:

select pgsodium.crypto_auth_hmacsha256_keygen() key \gset

select * from pgsodium.create_key('hmacsha256', raw_key:=:'external_key');

select id, key_type, parent_key, length(decrypted_raw_key) from pgsodium.decrypted_key where key_type = 'hmacsha256';

 */
#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kdf_keygen);
Datum
pgsodium_crypto_kdf_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_kdf_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kdf_derive_from_key);
Datum
pgsodium_crypto_kdf_derive_from_key (PG_FUNCTION_ARGS)
{
	size_t      subkey_size;
	size_t      result_size;
	unsigned long long subkey_id;
	bytea      *context;
	bytea      *primary_key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: subkey size cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: subkey id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: subkey context cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: primary key cannot be NULL");

	subkey_size = PG_GETARG_UINT32 (0);
	result_size = VARHDRSZ + subkey_size;
	subkey_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	primary_key = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (primary_key) != crypto_kdf_KEYBYTES,
		"%s: invalid derivation key");
	ERRORIF (subkey_size < crypto_kdf_BYTES_MIN ||
		subkey_size > crypto_kdf_BYTES_MAX, "%s: invalid key size requested");
	ERRORIF (VARSIZE_ANY_EXHDR (context) != 8, "%s: context must be 8 bytes");
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_derive_from_key (
		PGSODIUM_UCHARDATA (result),
		subkey_size,
		subkey_id,
		(const char *) VARDATA_ANY (context),
		PGSODIUM_UCHARDATA_ANY (primary_key));
	PG_RETURN_BYTEA_P (result);
}
