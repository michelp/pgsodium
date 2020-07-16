#ifndef PGSODIUM_H
#define PGSODIUM_H

#include <stdio.h>
#include <sodium.h>
#include <unistd.h>

#include "postgres.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"
#include "funcapi.h"
#include "access/htup_details.h"

#include "storage/ipc.h"
#include "utils/guc.h"
#include "port.h"
#include "miscadmin.h"

#define PG_GETKEY_EXEC	"pgsodium_getkey"

#define PGSODIUM_UCHARDATA(_vlena) (unsigned char*)VARDATA(_vlena)

typedef struct _pgsodium_cb {
  void* ptr;
  size_t size;
} _pgsodium_cb;

static void context_cb_zero_buff(void*);

static void
context_cb_zero_buff(void* a) {
  _pgsodium_cb *data = (_pgsodium_cb *) a;
  sodium_memzero(data->ptr, data->size);
}

static inline bytea* _pgsodium_zalloc_bytea(size_t);
static inline bytea* pgsodium_derive_helper(unsigned long long subkey_id, size_t subkey_size, bytea* context);

#define ERRORIF(B, msg)							\
  if ((B))										\
	ereport(									\
			ERROR,								\
			(errcode(ERRCODE_DATA_EXCEPTION),	\
			 errmsg(msg)))

void _PG_init(void);

/* Random data */

Datum pgsodium_randombytes_random(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_uniform(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_buf(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_seed(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_buf_deterministic(PG_FUNCTION_ARGS);

/* Secret key authenticated encryption */

Datum pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox_open(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox_by_id(PG_FUNCTION_ARGS);

/* Secret key authentication */

Datum pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_verify(PG_FUNCTION_ARGS);

/* Hashing */

Datum pgsodium_crypto_generichash_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_generichash(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_shorthash_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_shorthash(PG_FUNCTION_ARGS);

/* password Hashing */

Datum pgsodium_crypto_pwhash_saltgen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_pwhash(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_pwhash_str(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_pwhash_str_verify(PG_FUNCTION_ARGS);

/* Public Key */

Datum pgsodium_crypto_box_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_seed_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_noncegen(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_box(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_open(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_box_seal(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_seal_open(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_sign_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_seed_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_open(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_detached(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_verify_detached(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_init(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_update(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_final_create(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_final_verify(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_init(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_update(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_final_create(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_final_verify(PG_FUNCTION_ARGS);

/* Key Derivation */

Datum pgsodium_crypto_kdf_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_kdf_derive_from_key(PG_FUNCTION_ARGS);

/* Key Exchange */

Datum pgsodium_crypto_kx_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_kx_seed_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_kx_new_seed(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_kx_client_session_keys(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_kx_server_session_keys(PG_FUNCTION_ARGS);

/* Advanced */

Datum pgsodium_crypto_auth_hmacsha512_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_hmacsha512(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_hmacsha512_verify(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_auth_hmacsha256_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_hmacsha256(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_hmacsha256_verify(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_hash_sha256(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_hash_sha512(PG_FUNCTION_ARGS);

/* Server Managed Keys */

Datum pgsodium_derive(PG_FUNCTION_ARGS);

#endif /* PGSODIUM_H */
