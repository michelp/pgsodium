#ifndef PGSODIUM_H
#define PGSODIUM_H

#include <sodium.h>
#include "postgres.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"
#include "funcapi.h"
#include "access/htup_details.h"

void _PG_init(void);

/* Random data */

Datum pgsodium_randombytes_random(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_uniform(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_buf(PG_FUNCTION_ARGS);

/* Secret key authenticated encryption */

Datum pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_secretbox_open(PG_FUNCTION_ARGS);

/* Secret key authentication */

Datum pgsodium_crypto_auth(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_verify(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS);

/* Hashing */

Datum pgsodium_crypto_generichash(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_shorthash(PG_FUNCTION_ARGS);

/* Public Key */

Datum pgsodium_crypto_box_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_noncegen(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_box_open(PG_FUNCTION_ARGS);

Datum pgsodium_crypto_sign_keypair(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign(PG_FUNCTION_ARGS);
Datum pgsodium_crypto_sign_open(PG_FUNCTION_ARGS);

#endif /* PGSODIUM_H */
