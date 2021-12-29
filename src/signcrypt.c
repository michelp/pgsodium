#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_signcrypt_keypair);
Datum pgsodium_crypto_signcrypt_keypair(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *publickey;
    bytea *secretkey;
    size_t public_size = crypto_signcrypt_tbsbr_PUBLICKEYBYTES + VARHDRSZ;
    size_t secret_size = crypto_signcrypt_tbsbr_SECRETKEYBYTES + VARHDRSZ;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));
    publickey = _pgsodium_zalloc_bytea(public_size);
    secretkey = _pgsodium_zalloc_bytea(secret_size);
    crypto_signcrypt_tbsbr_keygen(PGSODIUM_UCHARDATA(publickey),
                                  PGSODIUM_UCHARDATA(secretkey));
    values[0] = PointerGetDatum(publickey);
    values[1] = PointerGetDatum(secretkey);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_signcrypt_sign_before);
Datum pgsodium_crypto_signcrypt_sign_before(PG_FUNCTION_ARGS) {
    bytea *sender = PG_GETARG_BYTEA_PP(0);
    bytea *recipient = PG_GETARG_BYTEA_PP(1);
    bytea *sender_sk = PG_GETARG_BYTEA_PP(2);
    bytea *recipient_pk = PG_GETARG_BYTEA_PP(3);
    bytea *additional = PG_GETARG_BYTEA_PP(4);

    TupleDesc tupdesc;
    Datum values[2];
    bool nulls[2] = {false, false};
    HeapTuple tuple;
    Datum result;
    bytea *state;
    bytea *shared_key;
    int success;
    size_t state_size = crypto_signcrypt_tbsbr_STATEBYTES + VARHDRSZ;
    size_t secret_size = crypto_signcrypt_tbsbr_SECRETKEYBYTES + VARHDRSZ;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function returning record called in context "
                        "that cannot accept type record")));

    state = _pgsodium_zalloc_bytea(state_size);
    shared_key = _pgsodium_zalloc_bytea(secret_size);

    success =
        crypto_signcrypt_tbsbr_sign_before(PGSODIUM_UCHARDATA(state),
                                           PGSODIUM_UCHARDATA(shared_key),
                                           PGSODIUM_UCHARDATA(sender),
                                           VARSIZE_ANY_EXHDR(sender),
                                           PGSODIUM_UCHARDATA(recipient),
                                           VARSIZE_ANY_EXHDR(recipient),
                                           PGSODIUM_UCHARDATA(additional),
                                           VARSIZE_ANY_EXHDR(additional),
                                           PGSODIUM_UCHARDATA(sender_sk),
                                           PGSODIUM_UCHARDATA(recipient_pk),
                                           NULL,
                                           0);

    ERRORIF(success != 0, "sign_before failed");
    values[0] = PointerGetDatum(state);
    values[1] = PointerGetDatum(shared_key);
    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);
    return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_signcrypt_sign_after);
Datum pgsodium_crypto_signcrypt_sign_after(PG_FUNCTION_ARGS) {
    bytea *state = PG_GETARG_BYTEA_PP(0);
    bytea *sender_sk = PG_GETARG_BYTEA_PP(1);
    bytea *ciphertext = PG_GETARG_BYTEA_PP(2);
    size_t sig_size = crypto_signcrypt_tbsbr_SIGNBYTES + VARHDRSZ;
    bytea *signature = _pgsodium_zalloc_bytea(sig_size);

    int success;

    success = crypto_signcrypt_tbsbr_sign_after(PGSODIUM_UCHARDATA(state),
                                                PGSODIUM_UCHARDATA(signature),
                                                PGSODIUM_UCHARDATA(sender_sk),
                                                PGSODIUM_UCHARDATA(ciphertext),
                                                VARSIZE_ANY_EXHDR(ciphertext));

    ERRORIF(success != 0, "sign_after failed");
    PG_RETURN_BYTEA_P(signature);
}
