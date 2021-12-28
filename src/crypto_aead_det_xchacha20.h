#ifndef crypto_aead_det_xchacha20_H
#define crypto_aead_det_xchacha20_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define crypto_aead_det_xchacha20_KEYBYTES 32
#define crypto_aead_det_xchacha20_ABYTES 32
#define crypto_aead_det_xchacha20_NONCEBYTES 16

int crypto_aead_det_xchacha20_encrypt_detached(
    unsigned char *c, unsigned char mac[crypto_aead_det_xchacha20_ABYTES], const unsigned char *m,
    size_t mlen, const unsigned char *ad, size_t adlen, const unsigned char *nonce,
    const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

int crypto_aead_det_xchacha20_decrypt_detached(
    unsigned char *m, const unsigned char *c, size_t clen,
    const unsigned char mac[crypto_aead_det_xchacha20_ABYTES], const unsigned char *ad,
    size_t adlen, const unsigned char *nonce,
    const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

int crypto_aead_det_xchacha20_encrypt(unsigned char *c, const unsigned char *m, size_t mlen,
                                      const unsigned char *ad, size_t adlen,
                                      const unsigned char *nonce,
                                      const unsigned char  k[crypto_aead_det_xchacha20_KEYBYTES]);

int crypto_aead_det_xchacha20_decrypt(unsigned char *m, const unsigned char *c, size_t clen,
                                      const unsigned char *ad, size_t adlen,
                                      const unsigned char *nonce,
                                      const unsigned char  k[crypto_aead_det_xchacha20_KEYBYTES]);

void crypto_aead_det_xchacha20_keygen(unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif