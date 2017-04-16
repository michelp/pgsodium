#ifndef PGSODIUM_H
#define PGSODIUM_H

#include "postgres.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"

void _PG_init(void);

Datum pgsodium_randombytes_random(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_uniform(PG_FUNCTION_ARGS);
Datum pgsodium_randombytes_buf(PG_FUNCTION_ARGS);

#endif // PGSODIUM_H
