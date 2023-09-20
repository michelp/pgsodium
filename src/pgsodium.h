#ifndef PGSODIUM_H
#define PGSODIUM_H

#include <stdio.h>
#include <sodium.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#include "postgres.h"
#include "commands/seclabel.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"
#include "funcapi.h"
#include "access/htup_details.h"

#include "storage/ipc.h"
#include "utils/guc.h"
#include "port.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_authid.h"
#include "miscadmin.h"

#include "crypto_aead_det_xchacha20.h"
#include "signcrypt_tbsbr.h"

#define elogn(s) elog(NOTICE, "%s", (s))
#define elogn1(s, v) elog(NOTICE, "%s: %lu", (s), (v))

#define PG_GETKEY_EXEC "pgsodium_getkey"

#define PGSODIUM_UCHARDATA(_vlena) (unsigned char *)VARDATA(_vlena)
#define PGSODIUM_CHARDATA(_vlena) (char *)VARDATA(_vlena)

#define PGSODIUM_UCHARDATA_ANY(_vlena) (unsigned char *)VARDATA_ANY(_vlena)
#define PGSODIUM_CHARDATA_ANY(_vlena) (char *)VARDATA_ANY(_vlena)

#define ERRORIF(B, msg)                                                        \
    if ((B))                                                                   \
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION), errmsg(msg, __func__)))

typedef struct _pgsodium_cb
{
	void       *ptr;
	size_t      size;
} _pgsodium_cb;

static void context_cb_zero_buff (void *);

static void
context_cb_zero_buff (void *a)
{
	_pgsodium_cb *data = (_pgsodium_cb *) a;
	sodium_memzero (data->ptr, data->size);
}

static inline bytea *_pgsodium_zalloc_bytea (size_t);
static inline bytea *pgsodium_derive_helper (unsigned long long subkey_id,
	size_t subkey_size, bytea * context);

extern PGDLLEXPORT bytea *pgsodium_secret_key;

/* allocator attached zero-callback to clean up memory */
static inline bytea *
_pgsodium_zalloc_bytea (size_t allocation_size)
{
	bytea      *result = (bytea *) palloc (allocation_size);
	MemoryContextCallback *ctxcb =
		(MemoryContextCallback *) MemoryContextAlloc (CurrentMemoryContext,
		sizeof (MemoryContextCallback));
	_pgsodium_cb *d = (_pgsodium_cb *) palloc (sizeof (_pgsodium_cb));
	d->ptr = result;
	d->size = allocation_size;
	ctxcb->func = context_cb_zero_buff;
	ctxcb->arg = d;
	MemoryContextRegisterResetCallback (CurrentMemoryContext, ctxcb);	// verify where this cb fires
	SET_VARSIZE (result, allocation_size);
	return result;
}

static inline text *
_pgsodium_zalloc_text (size_t allocation_size)
{
	text       *result = (text *) palloc (allocation_size);
	MemoryContextCallback *ctxcb =
		(MemoryContextCallback *) MemoryContextAlloc (CurrentMemoryContext,
		sizeof (MemoryContextCallback));
	_pgsodium_cb *d = (_pgsodium_cb *) palloc (sizeof (_pgsodium_cb));
	d->ptr = result;
	d->size = allocation_size;
	ctxcb->func = context_cb_zero_buff;
	ctxcb->arg = d;
	MemoryContextRegisterResetCallback (CurrentMemoryContext, ctxcb);
	SET_VARSIZE (result, allocation_size);
	return result;
}

static inline bytea *
pgsodium_derive_helper (unsigned long long subkey_id,
	size_t subkey_size, bytea * context)
{
	size_t      result_size;
	bytea      *result;
	ERRORIF (pgsodium_secret_key == NULL,
		"%s: pgsodium_derive: no server secret key defined.");
	ERRORIF (subkey_size < crypto_kdf_BYTES_MIN ||
		subkey_size > crypto_kdf_BYTES_MAX,
		"%s: crypto_kdf_derive_from_key: invalid key size requested");
	ERRORIF (VARSIZE_ANY_EXHDR (context) != 8,
		"%s: crypto_kdf_derive_from_key: context must be 8 bytes");
	result_size = VARHDRSZ + subkey_size;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_kdf_derive_from_key (PGSODIUM_UCHARDATA (result),
		subkey_size,
		subkey_id,
		(const char *) VARDATA_ANY (context),
		PGSODIUM_UCHARDATA (pgsodium_secret_key));
	return result;
}

PGDLLEXPORT void        _PG_init (void);

/* Random data */

PGDLLEXPORT Datum       pgsodium_randombytes_random (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_randombytes_uniform (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_randombytes_buf (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_randombytes_seed (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_randombytes_buf_deterministic (PG_FUNCTION_ARGS);

/* Secret key authenticated encryption */

PGDLLEXPORT Datum       pgsodium_crypto_secretbox_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_secretbox_noncegen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_secretbox (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_secretbox_open (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_secretbox_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_secretbox_open_by_id (PG_FUNCTION_ARGS);

/* Secret key authentication */

PGDLLEXPORT Datum       pgsodium_crypto_auth_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_verify (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_verify_by_id (PG_FUNCTION_ARGS);

/* Secret streams */

PGDLLEXPORT Datum
pgsodium_crypto_secretstream_xchacha20poly1305_keygen (PG_FUNCTION_ARGS);

/* AEAD */

PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_noncegen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_encrypt (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_decrypt (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_encrypt_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_ietf_decrypt_by_id (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_aead_det_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_det_encrypt (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_det_decrypt (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_det_encrypt_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_aead_det_decrypt_by_id (PG_FUNCTION_ARGS);

/* Hashing */

PGDLLEXPORT Datum       pgsodium_crypto_generichash_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_generichash (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_generichash_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_shorthash_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_shorthash (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_shorthash_by_id (PG_FUNCTION_ARGS);

/* password Hashing */

PGDLLEXPORT Datum       pgsodium_crypto_pwhash_saltgen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_pwhash (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_pwhash_str (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_pwhash_str_verify (PG_FUNCTION_ARGS);

/* Public Key */

PGDLLEXPORT Datum       pgsodium_crypto_box_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_box_seed_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_box_noncegen (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_box (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_box_open (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_box_seal (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_box_seal_open (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_sign_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_seed_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_open (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_detached (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_verify_detached (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_init (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_update (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_final_create (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_final_verify (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_init (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_update (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_final_create (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_sign_final_verify (PG_FUNCTION_ARGS);

/* Key Derivation */

PGDLLEXPORT Datum       pgsodium_crypto_kdf_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_kdf_derive_from_key (PG_FUNCTION_ARGS);

/* Key Exchange */

PGDLLEXPORT Datum       pgsodium_crypto_kx_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_kx_seed_keypair (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_kx_new_seed (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_kx_client_session_keys (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_kx_server_session_keys (PG_FUNCTION_ARGS);

/* Advanced */

PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha512_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha512 (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha512_verify (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha512_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha512_verify_by_id (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha256_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha256 (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha256_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha256_verify (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_auth_hmacsha256_verify_by_id (PG_FUNCTION_ARGS);

PGDLLEXPORT Datum       pgsodium_crypto_hash_sha256 (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_hash_sha512 (PG_FUNCTION_ARGS);

/* Server Managed Keys */

PGDLLEXPORT Datum       pgsodium_derive (PG_FUNCTION_ARGS);

/* Streaming */

PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_keygen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_noncegen (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20 (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_xor (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_xor_ic (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_xor_by_id (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_stream_xchacha20_xor_ic_by_id (PG_FUNCTION_ARGS);

/* Sign-Cryption */

PGDLLEXPORT Datum       pgsodium_crypto_signcrypt_sign_before (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_crypto_signcrypt_keypair (PG_FUNCTION_ARGS);

/* Helpers */

PGDLLEXPORT Datum       pgsodium_cmp (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_sodium_bin2base64 (PG_FUNCTION_ARGS);
PGDLLEXPORT Datum       pgsodium_sodium_base642bin (PG_FUNCTION_ARGS);

#endif /* PGSODIUM_H */
