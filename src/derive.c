#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_derive);
Datum pgsodium_derive(PG_FUNCTION_ARGS) {
    unsigned long long subkey_id = PG_GETARG_INT64(0);
    size_t subkey_size = PG_GETARG_UINT32(1);
    bytea *context = PG_GETARG_BYTEA_PP(2);
    PG_RETURN_BYTEA_P(pgsodium_derive_helper(subkey_id, subkey_size, context));
}
