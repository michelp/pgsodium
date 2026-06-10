/* doctest/ipcrypt
-- # IP Address Encryption
--
\pset linestyle unicode
\pset border 2
\pset pager off
create extension if not exists pgsodium; -- pragma:hide
set search_path to pgsodium,public; -- pragma:hide
--
-- libsodium (>= 1.0.21) provides the ipcrypt family of functions for
-- encrypting and anonymizing IP addresses, following the ipcrypt-std
-- specification (https://ipcrypt-std.github.io).
--
-- IP addresses are handled as the 16 byte binary form (IPv4 addresses
-- are represented as IPv4-mapped IPv6 addresses).  The crypto_ipcrypt_ip2bin()
-- and crypto_ipcrypt_bin2ip() helpers convert between text and binary forms.
--
*/

#include "pgsodium.h"

/* ---------------------------------------------------------------------------
 * Conversion helpers between text IP addresses and the 16 byte binary form.
 * ------------------------------------------------------------------------- */

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ip2bin);
Datum
pgsodium_crypto_ipcrypt_ip2bin (PG_FUNCTION_ARGS)
{
	text       *ip;
	char       *ipstr;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ip = PG_GETARG_TEXT_PP (0);
	ipstr = text_to_cstring (ip);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + 16);
	ERRORIF (sodium_ip2bin (PGSODIUM_UCHARDATA (result),
			ipstr, strlen (ipstr)) != 0,
		"%s: invalid IP address");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_bin2ip);
Datum
pgsodium_crypto_ipcrypt_bin2ip (PG_FUNCTION_ARGS)
{
	bytea      *bin;
	char        ipbuf[64];

	ERRORIF (PG_ARGISNULL (0), "%s: bin cannot be NULL");
	bin = PG_GETARG_BYTEA_PP (0);
	ERRORIF (VARSIZE_ANY_EXHDR (bin) != 16, "%s: input must be 16 bytes");
	ERRORIF (sodium_bin2ip (ipbuf, sizeof (ipbuf),
			PGSODIUM_UCHARDATA_ANY (bin)) == NULL,
		"%s: conversion failed");
	PG_RETURN_TEXT_P (cstring_to_text (ipbuf));
}

/* ---------------------------------------------------------------------------
 * Deterministic variant (AES-128, format-preserving).
 * key 16, input/output 16 bytes.
 * ------------------------------------------------------------------------- */

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_keygen);
Datum
pgsodium_crypto_ipcrypt_keygen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_KEYBYTES);
	crypto_ipcrypt_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_encrypt);
Datum
pgsodium_crypto_ipcrypt_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_BYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_BYTES);
	crypto_ipcrypt_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_decrypt);
Datum
pgsodium_crypto_ipcrypt_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_BYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_BYTES);
	crypto_ipcrypt_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_encrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_BYTES,
		"%s: invalid input");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_BYTES);
	crypto_ipcrypt_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_decrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_BYTES,
		"%s: invalid input");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_BYTES);
	crypto_ipcrypt_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

/* ---------------------------------------------------------------------------
 * Prefix-preserving variant (PFX, XOR of two AES-128 permutations).
 * key 32, input/output 16 bytes.  Preserves network prefix relationships.
 * ------------------------------------------------------------------------- */

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_pfx_keygen);
Datum
pgsodium_crypto_ipcrypt_pfx_keygen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_PFX_KEYBYTES);
	crypto_ipcrypt_pfx_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_pfx_encrypt);
Datum
pgsodium_crypto_ipcrypt_pfx_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_PFX_BYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_PFX_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_PFX_BYTES);
	crypto_ipcrypt_pfx_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_pfx_decrypt);
Datum
pgsodium_crypto_ipcrypt_pfx_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_PFX_BYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_PFX_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_PFX_BYTES);
	crypto_ipcrypt_pfx_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_pfx_encrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_pfx_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_PFX_BYTES,
		"%s: invalid input");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_PFX_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_PFX_BYTES);
	crypto_ipcrypt_pfx_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_pfx_decrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_pfx_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_PFX_BYTES,
		"%s: invalid input");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_PFX_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_PFX_BYTES);
	crypto_ipcrypt_pfx_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

/* ---------------------------------------------------------------------------
 * Non-deterministic variant (ND, KIASU-BC).
 * key 16, tweak 8, input 16, output 24 bytes (tweak prepended).
 * ------------------------------------------------------------------------- */

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_keygen);
Datum
pgsodium_crypto_ipcrypt_nd_keygen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_KEYBYTES);
	crypto_ipcrypt_nd_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_tweakgen);
Datum
pgsodium_crypto_ipcrypt_nd_tweakgen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_TWEAKBYTES);
	randombytes_buf (VARDATA (result), crypto_ipcrypt_ND_TWEAKBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_encrypt);
Datum
pgsodium_crypto_ipcrypt_nd_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *tweak;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: tweak cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	tweak = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_ND_INPUTBYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (tweak) != crypto_ipcrypt_ND_TWEAKBYTES,
		"%s: invalid tweak");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_ND_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_OUTPUTBYTES);
	crypto_ipcrypt_nd_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (tweak),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_decrypt);
Datum
pgsodium_crypto_ipcrypt_nd_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ct;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ct = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ct) != crypto_ipcrypt_ND_OUTPUTBYTES,
		"%s: invalid ciphertext");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_ND_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_INPUTBYTES);
	crypto_ipcrypt_nd_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ct), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_encrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_nd_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *tweak;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: tweak cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	tweak = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_ND_INPUTBYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (tweak) != crypto_ipcrypt_ND_TWEAKBYTES,
		"%s: invalid tweak");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_ND_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_OUTPUTBYTES);
	crypto_ipcrypt_nd_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (tweak),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_nd_decrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_nd_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ct;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ct = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ct) != crypto_ipcrypt_ND_OUTPUTBYTES,
		"%s: invalid ciphertext");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_ND_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_ND_INPUTBYTES);
	crypto_ipcrypt_nd_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ct), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

/* ---------------------------------------------------------------------------
 * Extended non-deterministic variant (NDX, AES-XTS).
 * key 32, tweak 16, input 16, output 32 bytes (tweak prepended).
 * ------------------------------------------------------------------------- */

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_keygen);
Datum
pgsodium_crypto_ipcrypt_ndx_keygen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_KEYBYTES);
	crypto_ipcrypt_ndx_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_tweakgen);
Datum
pgsodium_crypto_ipcrypt_ndx_tweakgen (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_TWEAKBYTES);
	randombytes_buf (VARDATA (result), crypto_ipcrypt_NDX_TWEAKBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_encrypt);
Datum
pgsodium_crypto_ipcrypt_ndx_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *tweak;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: tweak cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	tweak = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_NDX_INPUTBYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (tweak) != crypto_ipcrypt_NDX_TWEAKBYTES,
		"%s: invalid tweak");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_NDX_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_OUTPUTBYTES);
	crypto_ipcrypt_ndx_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (tweak),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_decrypt);
Datum
pgsodium_crypto_ipcrypt_ndx_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ct;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");
	ct = PG_GETARG_BYTEA_PP (0);
	key = PG_GETARG_BYTEA_PP (1);
	ERRORIF (VARSIZE_ANY_EXHDR (ct) != crypto_ipcrypt_NDX_OUTPUTBYTES,
		"%s: invalid ciphertext");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_ipcrypt_NDX_KEYBYTES,
		"%s: invalid key");
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_INPUTBYTES);
	crypto_ipcrypt_ndx_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ct), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_encrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_ndx_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ip;
	bytea      *tweak;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ip cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: tweak cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");
	ip = PG_GETARG_BYTEA_PP (0);
	tweak = PG_GETARG_BYTEA_PP (1);
	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);
	ERRORIF (VARSIZE_ANY_EXHDR (ip) != crypto_ipcrypt_NDX_INPUTBYTES,
		"%s: invalid input");
	ERRORIF (VARSIZE_ANY_EXHDR (tweak) != crypto_ipcrypt_NDX_TWEAKBYTES,
		"%s: invalid tweak");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_NDX_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_OUTPUTBYTES);
	crypto_ipcrypt_ndx_encrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ip), PGSODIUM_UCHARDATA_ANY (tweak),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_ipcrypt_ndx_decrypt_by_id);
Datum
pgsodium_crypto_ipcrypt_ndx_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ct;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key context cannot be NULL");
	ct = PG_GETARG_BYTEA_PP (0);
	key_id = PG_GETARG_INT64 (1);
	context = PG_GETARG_BYTEA_PP (2);
	ERRORIF (VARSIZE_ANY_EXHDR (ct) != crypto_ipcrypt_NDX_OUTPUTBYTES,
		"%s: invalid ciphertext");
	key = pgsodium_derive_helper (key_id, crypto_ipcrypt_NDX_KEYBYTES, context);
	result = _pgsodium_zalloc_bytea (VARHDRSZ + crypto_ipcrypt_NDX_INPUTBYTES);
	crypto_ipcrypt_ndx_decrypt (PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ct), PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}
