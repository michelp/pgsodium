#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth);
Datum pgsodium_crypto_auth(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_P(0);
    bytea *key = PG_GETARG_BYTEA_P(1);
    int result_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "%s: invalid key");
    result_size = VARHDRSZ + crypto_auth_BYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_auth(PGSODIUM_UCHARDATA(result),
                PGSODIUM_UCHARDATA(message),
                VARSIZE_ANY_EXHDR(message),
                PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_by_id);
Datum pgsodium_crypto_auth_by_id(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_P(0);
    unsigned long long key_id = PG_GETARG_INT64(1);
    bytea *context = PG_GETARG_BYTEA_P(2);
    bytea *key = pgsodium_derive_helper(key_id, crypto_auth_KEYBYTES, context);
    int result_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "%s: invalid key");
    result_size = VARHDRSZ + crypto_auth_BYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_auth(PGSODIUM_UCHARDATA(result),
                PGSODIUM_UCHARDATA(message),
                VARSIZE_ANY_EXHDR(message),
                PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_verify);
Datum pgsodium_crypto_auth_verify(PG_FUNCTION_ARGS) {
    int success;
    bytea *mac = PG_GETARG_BYTEA_P(0);
    bytea *message = PG_GETARG_BYTEA_P(1);
    bytea *key = PG_GETARG_BYTEA_P(2);
    ERRORIF(VARSIZE_ANY_EXHDR(mac) != crypto_auth_BYTES, "%s: invalid mac");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "%s: invalid key");
    success = crypto_auth_verify(PGSODIUM_UCHARDATA(mac),
                                 PGSODIUM_UCHARDATA(message),
                                 VARSIZE_ANY_EXHDR(message),
                                 PGSODIUM_UCHARDATA(key));
    PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_verify_by_id);
Datum pgsodium_crypto_auth_verify_by_id(PG_FUNCTION_ARGS) {
    int success;
    bytea *mac = PG_GETARG_BYTEA_P(0);
    bytea *message = PG_GETARG_BYTEA_P(1);
    unsigned long long key_id = PG_GETARG_INT64(2);
    bytea *context = PG_GETARG_BYTEA_P(3);
    bytea *key =
        pgsodium_derive_helper(key_id, crypto_secretbox_KEYBYTES, context);

    ERRORIF(VARSIZE_ANY_EXHDR(mac) != crypto_auth_BYTES, "%s: invalid mac");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "%s: invalid key");
    success = crypto_auth_verify(PGSODIUM_UCHARDATA(mac),
                                 PGSODIUM_UCHARDATA(message),
                                 VARSIZE_ANY_EXHDR(message),
                                 PGSODIUM_UCHARDATA(key));
    PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_keygen);
Datum pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_auth_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
    PG_RETURN_BYTEA_P(result);
}
