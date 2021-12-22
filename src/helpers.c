#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_cmp);
Datum pgsodium_cmp(PG_FUNCTION_ARGS) {
    int i = 0;
    int m = 0;

    bytea *X = PG_GETARG_BYTEA_P(0);
    bytea *Y = PG_GETARG_BYTEA_P(1);
    size_t xlen = VARSIZE_ANY(X);
    size_t ylen = VARSIZE_ANY(Y);
    char * x = VARDATA_ANY(X);
    char * y = VARDATA_ANY(Y);
    
    if (xlen != ylen)
        PG_RETURN_BOOL(false);

    for (i = 0; i < xlen; i++)
        m |= x[i] ^ y[i];

    PG_RETURN_BOOL(m == 0);
}
