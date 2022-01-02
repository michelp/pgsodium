#include "pgsodium.h"

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_keygen);
Datum pgsodium_crypto_aead_ietf_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    crypto_aead_chacha20poly1305_ietf_keygen(PGSODIUM_UCHARDATA(result));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_noncegen);
Datum pgsodium_crypto_aead_ietf_noncegen(PG_FUNCTION_ARGS) {
    int result_size = VARHDRSZ + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    randombytes_buf(VARDATA(result),
                    crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_encrypt);
Datum pgsodium_crypto_aead_ietf_encrypt(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *nonce = PG_GETARG_BYTEA_PP(2);
    bytea *key = PG_GETARG_BYTEA_PP(3);
    unsigned long long result_size;
    bytea *result;
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) !=
                crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) !=
                crypto_aead_chacha20poly1305_IETF_KEYBYTES,
            "invalid key");

    result_size =
        VARSIZE_ANY(message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_aead_chacha20poly1305_ietf_encrypt(PGSODIUM_UCHARDATA(result),
                                              &result_size,
                                              PGSODIUM_UCHARDATA(message),
                                              VARSIZE_ANY_EXHDR(message),
                                              PGSODIUM_UCHARDATA(additional),
                                              VARSIZE_ANY_EXHDR(additional),
                                              NULL,
                                              PGSODIUM_UCHARDATA(nonce),
                                              PGSODIUM_UCHARDATA(key));
    SET_VARSIZE(result,
                result_size + VARHDRSZ +
                    crypto_aead_chacha20poly1305_IETF_ABYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_decrypt);
Datum pgsodium_crypto_aead_ietf_decrypt(PG_FUNCTION_ARGS) {
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *nonce = PG_GETARG_BYTEA_PP(2);
    bytea *key = PG_GETARG_BYTEA_PP(3);
    size_t ciphertext_len;
    unsigned long long result_size;
    bytea *result;
    int success;

    ERRORIF(VARSIZE_ANY_EXHDR(ciphertext) <=
                crypto_aead_chacha20poly1305_IETF_ABYTES,
            "invalid message");
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) !=
                crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            "invalid nonce");
    ERRORIF(VARSIZE_ANY_EXHDR(key) !=
                crypto_aead_chacha20poly1305_IETF_KEYBYTES,
            "invalid key");

    ciphertext_len = VARSIZE_ANY_EXHDR(ciphertext) -
                     crypto_aead_chacha20poly1305_IETF_ABYTES;
    result = _pgsodium_zalloc_bytea(ciphertext_len);

    success = crypto_aead_chacha20poly1305_ietf_decrypt(
        PGSODIUM_UCHARDATA(result),
        &result_size,
        NULL,
        PGSODIUM_UCHARDATA(ciphertext),
        ciphertext_len,
        PGSODIUM_UCHARDATA(additional),
        VARSIZE_ANY_EXHDR(additional),
        PGSODIUM_UCHARDATA(nonce),
        PGSODIUM_UCHARDATA(key));
    ERRORIF(success != 0, "invalid ciphertext");
    SET_VARSIZE(result, VARHDRSZ + result_size);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_encrypt_by_id);
Datum pgsodium_crypto_aead_ietf_encrypt_by_id(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *nonce = PG_GETARG_BYTEA_PP(2);
    unsigned long long key_id = PG_GETARG_INT64(3);
    bytea *context = PG_GETARG_BYTEA_PP(4);
    unsigned long long result_size;
    bytea *result;
    bytea *key;
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) !=
                crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            "invalid nonce");
    key = pgsodium_derive_helper(
        key_id, crypto_aead_chacha20poly1305_IETF_KEYBYTES, context);
    result_size =
        VARSIZE_ANY(message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_aead_chacha20poly1305_ietf_encrypt(PGSODIUM_UCHARDATA(result),
                                              &result_size,
                                              PGSODIUM_UCHARDATA(message),
                                              VARSIZE_ANY_EXHDR(message),
                                              PGSODIUM_UCHARDATA(additional),
                                              VARSIZE_ANY_EXHDR(additional),
                                              NULL,
                                              PGSODIUM_UCHARDATA(nonce),
                                              PGSODIUM_UCHARDATA(key));
    SET_VARSIZE(result,
                VARHDRSZ + result_size +
                    crypto_aead_chacha20poly1305_IETF_ABYTES);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_ietf_decrypt_by_id);
Datum pgsodium_crypto_aead_ietf_decrypt_by_id(PG_FUNCTION_ARGS) {
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *nonce = PG_GETARG_BYTEA_PP(2);
    unsigned long long key_id = PG_GETARG_INT64(3);
    bytea *context = PG_GETARG_BYTEA_PP(4);
    size_t ciphertext_len;
    unsigned long long result_size;
    bytea *result;
    bytea *key;
    int success;
    ERRORIF(VARSIZE_ANY_EXHDR(ciphertext) <=
                crypto_aead_chacha20poly1305_IETF_ABYTES,
            "invalid message");
    ERRORIF(VARSIZE_ANY_EXHDR(nonce) !=
                crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            "invalid nonce");
    key = pgsodium_derive_helper(
        key_id, crypto_aead_chacha20poly1305_IETF_KEYBYTES, context);

    ciphertext_len = VARSIZE_ANY_EXHDR(ciphertext) -
                     crypto_aead_chacha20poly1305_IETF_ABYTES;
    result = _pgsodium_zalloc_bytea(ciphertext_len);

    success = crypto_aead_chacha20poly1305_ietf_decrypt(
        PGSODIUM_UCHARDATA(result),
        &result_size,
        NULL,
        PGSODIUM_UCHARDATA(ciphertext),
        ciphertext_len,
        PGSODIUM_UCHARDATA(additional),
        VARSIZE_ANY_EXHDR(additional),
        PGSODIUM_UCHARDATA(nonce),
        PGSODIUM_UCHARDATA(key));
    ERRORIF(success != 0, "invalid ciphertext");
    SET_VARSIZE(result, VARHDRSZ + result_size);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_det_keygen);
Datum pgsodium_crypto_aead_det_keygen(PG_FUNCTION_ARGS) {
    size_t result_size = VARHDRSZ + crypto_aead_det_xchacha20_KEYBYTES;
    bytea *result = _pgsodium_zalloc_bytea(result_size);
    crypto_aead_det_xchacha20_keygen(PGSODIUM_UCHARDATA(result));
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_det_encrypt);
Datum pgsodium_crypto_aead_det_encrypt(PG_FUNCTION_ARGS) {
    bytea *message = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *key = PG_GETARG_BYTEA_PP(2);
    bytea *nonce;
    size_t result_size;
    bytea *result;

    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_aead_det_xchacha20_KEYBYTES,
            "invalid key");

    if (!PG_ARGISNULL(3))
        nonce = PG_GETARG_BYTEA_PP(3);
    else
        nonce = NULL;
    result_size = VARSIZE_ANY_EXHDR(message) + crypto_aead_det_xchacha20_ABYTES;
    result = _pgsodium_zalloc_bytea(result_size);
    crypto_aead_det_xchacha20_encrypt(
        PGSODIUM_UCHARDATA(result),
        PGSODIUM_UCHARDATA(message),
        VARSIZE_ANY_EXHDR(message),
        PGSODIUM_UCHARDATA(additional),
        VARSIZE_ANY_EXHDR(additional),
        nonce != NULL ? PGSODIUM_UCHARDATA(additional) : NULL,
        PGSODIUM_UCHARDATA(key));
    SET_VARSIZE(result, VARHDRSZ + result_size);
    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_aead_det_decrypt);
Datum pgsodium_crypto_aead_det_decrypt(PG_FUNCTION_ARGS) {
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    bytea *additional = PG_GETARG_BYTEA_PP(1);
    bytea *key = PG_GETARG_BYTEA_PP(2);
    size_t result_len;
    bytea *result;
    int success;
    ERRORIF(VARSIZE_ANY_EXHDR(ciphertext) <= crypto_aead_det_xchacha20_ABYTES,
            "invalid message");
    ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_aead_det_xchacha20_KEYBYTES,
            "invalid key");
    result_len =
        VARSIZE_ANY_EXHDR(ciphertext) - crypto_aead_det_xchacha20_ABYTES;
    result = _pgsodium_zalloc_bytea(result_len);
    success = crypto_aead_det_xchacha20_decrypt(PGSODIUM_UCHARDATA(result),
                                                PGSODIUM_UCHARDATA(ciphertext),
                                                VARSIZE_ANY_EXHDR(ciphertext),
                                                PGSODIUM_UCHARDATA(additional),
                                                VARSIZE_ANY_EXHDR(additional),
                                                NULL,
                                                PGSODIUM_UCHARDATA(key));
    ERRORIF(success != 0, "invalid ciphertext");
    SET_VARSIZE(result, VARHDRSZ + result_len);
    PG_RETURN_BYTEA_P(result);
}
