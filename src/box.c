#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_keypair);
Datum pgsodium_crypto_box_keypair(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *publickey;
    bytea *secretkey;
    size_t public_size = crypto_box_PUBLICKEYBYTES + VARHDRSZ;
    size_t secret_size = crypto_box_SECRETKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    publickey = _pgsodium_zalloc_bytea(public_size);
    secretkey = _pgsodium_zalloc_bytea(secret_size);
    crypto_box_keypair(PGSODIUM_UCHARDATA(publickey),
                       PGSODIUM_UCHARDATA(secretkey));
    values[0] = PointerGetDatum(publickey);
    values[1] = PointerGetDatum(secretkey);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_new_seed);
Datum pgsodium_crypto_box_new_seed(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_box_SEEDBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result), crypto_box_SEEDBYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seed_keypair);
Datum pgsodium_crypto_box_seed_keypair(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *publickey;
    bytea *secretkey;
    bytea *seed = PG_GETARG_BYTEA_PP(0);
    size_t public_size = crypto_box_PUBLICKEYBYTES + VARHDRSZ;
    size_t secret_size = crypto_box_SECRETKEYBYTES + VARHDRSZ;
    ERRORIF(VARSIZE_ANY_EXHDR(seed) != crypto_box_SEEDBYTES, "invalid seed");
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    publickey = _pgsodium_zalloc_bytea(public_size);
    secretkey = _pgsodium_zalloc_bytea(secret_size);
    crypto_box_seed_keypair(PGSODIUM_UCHARDATA(publickey),
                            PGSODIUM_UCHARDATA(secretkey),
                            PGSODIUM_UCHARDATA(seed));
    values[0] = PointerGetDatum(publickey);
    values[1] = PointerGetDatum(secretkey);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_noncegen);
Datum pgsodium_crypto_box_noncegen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_box_NONCEBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result), crypto_box_NONCEBYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box);
Datum pgsodium_crypto_box(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *nonce = PG_GETARG_BYTEA_PP(1);
    bytea *publickey = PG_GETARG_BYTEA_PP(2);
    bytea *secretkey = PG_GETARG_BYTEA_PP(3);
    int success;
    size_t message_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_box_NONCEBYTES, "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(publickey) != crypto_box_PUBLICKEYBYTES,
            "invalid public key");
    ERRORIF(VARSIZE_ANY_EXHDR(secretkey) != crypto_box_SECRETKEYBYTES,
            "invalid secret key");

    message_size = crypto_box_MACBYTES + VARSIZE_ANY(message);
    result = _pgsodium_zalloc_bytea(message_size);
    success = crypto_box_easy(PGSODIUM_UCHARDATA(result),
                              PGSODIUM_UCHARDATA(message),
                              VARSIZE_ANY_EXHDR(message),
                              PGSODIUM_UCHARDATA(nonce),
                              PGSODIUM_UCHARDATA(publickey),
                              PGSODIUM_UCHARDATA(secretkey));
    ERRORIF(success != 0, "invalid message");
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_open);
Datum pgsodium_crypto_box_open(PG_FUNCTION_ARGS) {
    int success;
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *nonce = PG_GETARG_BYTEA_PP(1);
    bytea *publickey = PG_GETARG_BYTEA_PP(2);
    bytea *secretkey = PG_GETARG_BYTEA_PP(3);
    size_t message_size;
    bytea *result;

    ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_box_NONCEBYTES, "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(publickey) != crypto_box_PUBLICKEYBYTES,
            "invalid public key");
    ERRORIF(VARSIZE_ANY_EXHDR(secretkey) != crypto_box_SECRETKEYBYTES,
            "invalid secret key");
    ERRORIF(VARSIZE_ANY_EXHDR(message) <= crypto_box_MACBYTES,
            "invalid message");

    message_size = VARSIZE_ANY(message) - crypto_box_MACBYTES;
    result = _pgsodium_zalloc_bytea(message_size);
    success = crypto_box_open_easy(PGSODIUM_UCHARDATA(result),
                                   PGSODIUM_UCHARDATA(message),
                                   VARSIZE_ANY_EXHDR(message),
                                   PGSODIUM_UCHARDATA(nonce),
                                   PGSODIUM_UCHARDATA(publickey),
                                   PGSODIUM_UCHARDATA(secretkey));
    ERRORIF(success != 0, "invalid message");
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal);
Datum pgsodium_crypto_box_seal(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *public_key = PG_GETARG_BYTEA_PP(1);
    size_t result_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(public_key) != crypto_box_PUBLICKEYBYTES,
            "invalid public key");
    result_size = crypto_box_SEALBYTES + VARSIZE(message);
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_box_seal(PGSODIUM_UCHARDATA(result),
                    PGSODIUM_UCHARDATA(message),
                    VARSIZE_ANY_EXHDR(message),
                    PGSODIUM_UCHARDATA(public_key));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal_open);
Datum pgsodium_crypto_box_seal_open(PG_FUNCTION_ARGS) {
    int success;
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    bytea *public_key = PG_GETARG_BYTEA_PP(1);
    bytea *secret_key = PG_GETARG_BYTEA_PP(2);
    size_t result_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(public_key) != crypto_box_PUBLICKEYBYTES,
            "invalid public key");
    ERRORIF(VARSIZE_ANY_EXHDR(secret_key) != crypto_box_SECRETKEYBYTES,
            "invalid secret key");
    ERRORIF(VARSIZE_ANY_EXHDR(ciphertext) <= crypto_box_SEALBYTES,
            "invalid message");

    result_size = VARSIZE(ciphertext) - crypto_box_SEALBYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    success = crypto_box_seal_open(PGSODIUM_UCHARDATA(result),
                                   PGSODIUM_UCHARDATA(ciphertext),
                                   VARSIZE_ANY_EXHDR(ciphertext),
                                   PGSODIUM_UCHARDATA(public_key),
                                   PGSODIUM_UCHARDATA(secret_key));
    ERRORIF(success != 0, "invalid message");
    PG_RETURN_BYTEA_P(result);
}
