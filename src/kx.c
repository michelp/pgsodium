#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_seed_keypair);
Datum pgsodium_crypto_kx_seed_keypair(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *publickey;
    bytea *secretkey;
    bytea *seed = PG_GETARG_BYTEA_PP(0);
    size_t public_size = crypto_kx_PUBLICKEYBYTES + VARHDRSZ;
    size_t secret_size = crypto_kx_SECRETKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    ERRORIF(VARSIZE_ANY_EXHDR(seed) != crypto_kx_SEEDBYTES, "invalid seed");
    publickey = _pgsodium_zalloc_bytea(public_size);
    secretkey = _pgsodium_zalloc_bytea(secret_size);
    crypto_kx_seed_keypair(PGSODIUM_UCHARDATA(publickey),
                           PGSODIUM_UCHARDATA(secretkey),
                           PGSODIUM_UCHARDATA(seed));
    values[0] = PointerGetDatum(publickey);
    values[1] = PointerGetDatum(secretkey);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_new_seed);
Datum pgsodium_crypto_kx_new_seed(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_kx_SEEDBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result), crypto_kx_SEEDBYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_client_session_keys);
Datum pgsodium_crypto_kx_client_session_keys(PG_FUNCTION_ARGS) {
    int success;
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *rx;
    bytea *tx;
    bytea *client_pk = PG_GETARG_BYTEA_PP(0);
    bytea *client_sk = PG_GETARG_BYTEA_PP(1);
    bytea *server_pk = PG_GETARG_BYTEA_PP(2);
    size_t rx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
    size_t tx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    ERRORIF(VARSIZE_ANY_EXHDR(client_pk) != crypto_kx_PUBLICKEYBYTES,
            "bad client public key");
    ERRORIF(VARSIZE_ANY_EXHDR(client_sk) != crypto_kx_SECRETKEYBYTES,
            "bad client secret key");
    ERRORIF(VARSIZE_ANY_EXHDR(server_pk) != crypto_kx_PUBLICKEYBYTES,
            "bad server public key");
    rx = _pgsodium_zalloc_bytea(rx_size);
    tx = _pgsodium_zalloc_bytea(tx_size);
    success = crypto_kx_client_session_keys(PGSODIUM_UCHARDATA(rx),
                                            PGSODIUM_UCHARDATA(tx),
                                            PGSODIUM_UCHARDATA(client_pk),
                                            PGSODIUM_UCHARDATA(client_sk),
                                            PGSODIUM_UCHARDATA(server_pk));
    ERRORIF(success != 0, "invalid message");
    values[0] = PointerGetDatum(rx);
    values[1] = PointerGetDatum(tx);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_server_session_keys);
Datum pgsodium_crypto_kx_server_session_keys(PG_FUNCTION_ARGS) {
    int success;
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *rx;
    bytea *tx;
    bytea *server_pk = PG_GETARG_BYTEA_PP(0);
    bytea *server_sk = PG_GETARG_BYTEA_PP(1);
    bytea *client_pk = PG_GETARG_BYTEA_PP(2);
    size_t rx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
    size_t tx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    ERRORIF(VARSIZE_ANY_EXHDR(server_pk) != crypto_kx_PUBLICKEYBYTES,
            "bad server public key");
    ERRORIF(VARSIZE_ANY_EXHDR(server_sk) != crypto_kx_SECRETKEYBYTES,
            "bad server secret key");
    ERRORIF(VARSIZE_ANY_EXHDR(client_pk) != crypto_kx_PUBLICKEYBYTES,
            "bad client public key");
    rx = _pgsodium_zalloc_bytea(rx_size);
    tx = _pgsodium_zalloc_bytea(tx_size);
    success = crypto_kx_server_session_keys(PGSODIUM_UCHARDATA(rx),
                                            PGSODIUM_UCHARDATA(tx),
                                            PGSODIUM_UCHARDATA(server_pk),
                                            PGSODIUM_UCHARDATA(server_sk),
                                            PGSODIUM_UCHARDATA(client_pk));
    ERRORIF(success != 0, "invalid message");
    values[0] = PointerGetDatum(rx);
    values[1] = PointerGetDatum(tx);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_keypair);
Datum pgsodium_crypto_kx_keypair(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *publickey;
    bytea *secretkey;
    size_t public_size = crypto_kx_PUBLICKEYBYTES + VARHDRSZ;
    size_t secret_size = crypto_kx_SECRETKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    publickey = _pgsodium_zalloc_bytea(public_size);
    secretkey = _pgsodium_zalloc_bytea(secret_size);
    crypto_kx_keypair(PGSODIUM_UCHARDATA(publickey),
                      PGSODIUM_UCHARDATA(secretkey));
    values[0] = PointerGetDatum(publickey);
    values[1] = PointerGetDatum(secretkey);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}
