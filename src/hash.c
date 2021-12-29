#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash_keygen);
Datum pgsodium_crypto_generichash_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_generichash_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result), result_size);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash);
Datum pgsodium_crypto_generichash(PG_FUNCTION_ARGS) {
    bytea *data;
    bytea *result;
    bytea *keyarg;
    unsigned char *key = NULL;
    size_t keylen = 0;
    size_t result_size;
    data = PG_GETARG_BYTEA_PP(0);
    if (!PG_ARGISNULL(1)) {
        keyarg = PG_GETARG_BYTEA_PP(1);
        key = PGSODIUM_UCHARDATA(keyarg);
        keylen = VARSIZE_ANY_EXHDR(keyarg);
        ERRORIF(keylen < crypto_generichash_KEYBYTES_MIN ||
                    keylen > crypto_generichash_KEYBYTES_MAX,
                "invalid key");
    }
    result_size = VARHDRSZ + crypto_generichash_BYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_generichash(PGSODIUM_UCHARDATA(result),
                       crypto_generichash_BYTES,
                       PGSODIUM_UCHARDATA(data),
                       VARSIZE_ANY_EXHDR(data),
                       key,
                       keylen);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash_keygen);
Datum pgsodium_crypto_shorthash_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_shorthash_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash);
Datum pgsodium_crypto_shorthash(PG_FUNCTION_ARGS) {
    bytea *data;
    bytea *result;
    bytea *key;
    int result_size = VARHDRSZ + crypto_shorthash_BYTES;
    data = PG_GETARG_BYTEA_PP(0);
    key = PG_GETARG_BYTEA_PP(1);
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_shorthash_KEYBYTES, "invalid key");
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_shorthash(PGSODIUM_UCHARDATA(result),
                     PGSODIUM_UCHARDATA(data),
                     VARSIZE_ANY_EXHDR(data),
                     PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash_by_id);
Datum pgsodium_crypto_generichash_by_id(PG_FUNCTION_ARGS) {
    bytea *data;
    bytea *result;
    bytea *keyarg;
    bytea *context;
    unsigned char *key = NULL;
    size_t keylen = 0;
    size_t result_size;
    data = PG_GETARG_BYTEA_PP(0);
    if (!PG_ARGISNULL(1)) {
        unsigned long long key_id = PG_GETARG_INT64(1);
        context = PG_GETARG_BYTEA_PP(2);
        keyarg = pgsodium_derive_helper(
            key_id, crypto_generichash_KEYBYTES, context);
        key = PGSODIUM_UCHARDATA(keyarg);
        keylen = VARSIZE_ANY_EXHDR(keyarg);
        ERRORIF(keylen < crypto_generichash_KEYBYTES_MIN ||
                    keylen > crypto_generichash_KEYBYTES_MAX,
                "invalid key");
    }
    result_size = VARHDRSZ + crypto_generichash_BYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_generichash(PGSODIUM_UCHARDATA(result),
                       crypto_generichash_BYTES,
                       PGSODIUM_UCHARDATA(data),
                       VARSIZE_ANY_EXHDR(data),
                       key,
                       keylen);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash_by_id);
Datum pgsodium_crypto_shorthash_by_id(PG_FUNCTION_ARGS) {
    bytea *data;
    bytea *result;
    bytea *key;
    bytea *context;
    uint64_t key_id;
    int result_size = VARHDRSZ + crypto_shorthash_BYTES;
    data = PG_GETARG_BYTEA_PP(0);
    key_id = PG_GETARG_INT64(1);
    context = PG_GETARG_BYTEA_PP(2);
    key = pgsodium_derive_helper(key_id, crypto_shorthash_KEYBYTES, context);
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_shorthash(PGSODIUM_UCHARDATA(result),
                     PGSODIUM_UCHARDATA(data),
                     VARSIZE_ANY_EXHDR(data),
                     PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}
