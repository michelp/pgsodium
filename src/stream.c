
#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_keygen);
Datum pgsodium_crypto_stream_xchacha20_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_stream_xchacha20_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    crypto_stream_xchacha20_keygen(PGSODIUM_UCHARDATA(result));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_noncegen);
Datum pgsodium_crypto_stream_xchacha20_noncegen(PG_FUNCTION_ARGS) {
    uint64_t result_size = VARHDRSZ + crypto_stream_xchacha20_NONCEBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result), crypto_stream_xchacha20_NONCEBYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20);
Datum pgsodium_crypto_stream_xchacha20(PG_FUNCTION_ARGS) {
    size_t size = PG_GETARG_INT64(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    bytea *key = PG_GETARG_BYTEA_P(2);
    uint64_t result_size = VARHDRSZ + size;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");

    crypto_stream_xchacha20(PGSODIUM_UCHARDATA(result),
                            result_size,
                            PGSODIUM_UCHARDATA(nonce),
                            PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_xor);
Datum pgsodium_crypto_stream_xchacha20_xor(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_P(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    bytea *key = PG_GETARG_BYTEA_P(2);
    uint64_t result_size = VARSIZE_ANY(data);
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");

    crypto_stream_xchacha20_xor(PGSODIUM_UCHARDATA(result),
                                PGSODIUM_UCHARDATA(data),
                                result_size,
                                PGSODIUM_UCHARDATA(nonce),
                                PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_xor_ic);
Datum pgsodium_crypto_stream_xchacha20_xor_ic(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_P(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    uint64_t ic = PG_GETARG_INT64(2);
    bytea *key = PG_GETARG_BYTEA_P(3);
    uint64_t result_size = VARSIZE_ANY(data);
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");
    crypto_stream_xchacha20_xor_ic(PGSODIUM_UCHARDATA(result),
                                   PGSODIUM_UCHARDATA(data),
                                   result_size,
                                   PGSODIUM_UCHARDATA(nonce),
                                   ic,
                                   PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_by_id);
Datum pgsodium_crypto_stream_xchacha20_by_id(PG_FUNCTION_ARGS) {
    size_t size = PG_GETARG_INT64(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    uint64_t key_id = PG_GETARG_INT64(2);
    bytea *context = PG_GETARG_BYTEA_P(3);
    bytea *key = pgsodium_derive_helper(
        key_id, crypto_stream_xchacha20_KEYBYTES, context);

    uint64_t result_size = VARHDRSZ + size;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");

    crypto_stream_xchacha20(PGSODIUM_UCHARDATA(result),
                            result_size,
                            PGSODIUM_UCHARDATA(nonce),
                            PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_xor_by_id);
Datum pgsodium_crypto_stream_xchacha20_xor_by_id(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_P(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    uint64_t key_id = PG_GETARG_INT64(2);
    bytea *context = PG_GETARG_BYTEA_P(3);
    bytea *key = pgsodium_derive_helper(
        key_id, crypto_stream_xchacha20_KEYBYTES, context);
    uint64_t result_size = VARSIZE_ANY(data);
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");

    crypto_stream_xchacha20_xor(PGSODIUM_UCHARDATA(result),
                                PGSODIUM_UCHARDATA(data),
                                result_size,
                                PGSODIUM_UCHARDATA(nonce),
                                PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_stream_xchacha20_xor_ic_by_id);
Datum pgsodium_crypto_stream_xchacha20_xor_ic_by_id(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_P(0);
    bytea *nonce = PG_GETARG_BYTEA_P(1);
    uint64_t ic = PG_GETARG_INT64(2);
    uint64_t key_id = PG_GETARG_INT64(3);
    bytea *context = PG_GETARG_BYTEA_P(4);
    bytea *key = pgsodium_derive_helper(
        key_id, crypto_stream_xchacha20_KEYBYTES, context);
    uint64_t result_size = VARSIZE_ANY(data);
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_stream_xchacha20_NONCEBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_stream_xchacha20_KEYBYTES,
            "invalid key");

    crypto_stream_xchacha20_xor_ic(PGSODIUM_UCHARDATA(result),
                                   PGSODIUM_UCHARDATA(data),
                                   result_size,
                                   PGSODIUM_UCHARDATA(nonce),
                                   ic,
                                   PGSODIUM_UCHARDATA(key));
    PG_RETURN_BYTEA_P(result);
}
