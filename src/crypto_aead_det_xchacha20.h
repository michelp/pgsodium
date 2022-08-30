/* BSD 2-Clause License */

/* Copyright (c) 2020, Frank Denis */
/* All rights reserved. */

/* Redistribution and use in source and binary forms, with or without */
/* modification, are permitted provided that the following conditions are met: */

/* * Redistributions of source code must retain the above copyright notice, this */
/*   list of conditions and the following disclaimer. */

/* * Redistributions in binary form must reproduce the above copyright notice, */
/*   this list of conditions and the following disclaimer in the documentation */
/*   and/or other materials provided with the distribution. */

/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" */
/* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE */
/* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE */
/* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE */
/* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL */
/* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR */
/* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER */
/* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, */
/* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE */
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifndef crypto_aead_det_xchacha20_H
#define crypto_aead_det_xchacha20_H

#ifdef __cplusplus
extern      "C"
{
#endif

#include <stdlib.h>

#define crypto_aead_det_xchacha20_KEYBYTES 32
#define crypto_aead_det_xchacha20_ABYTES 32
#define crypto_aead_det_xchacha20_NONCEBYTES 16

	int         crypto_aead_det_xchacha20_encrypt_detached (unsigned char *c,
		unsigned char mac[crypto_aead_det_xchacha20_ABYTES],
		const unsigned char *m, size_t mlen, const unsigned char *ad,
		size_t adlen, const unsigned char *nonce,
		const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

	int         crypto_aead_det_xchacha20_decrypt_detached (unsigned char *m,
		const unsigned char *c, size_t clen,
		const unsigned char mac[crypto_aead_det_xchacha20_ABYTES],
		const unsigned char *ad, size_t adlen, const unsigned char *nonce,
		const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

	int         crypto_aead_det_xchacha20_encrypt (unsigned char *c,
		const unsigned char *m, size_t mlen, const unsigned char *ad,
		size_t adlen, const unsigned char *nonce,
		const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

	int         crypto_aead_det_xchacha20_decrypt (unsigned char *m,
		const unsigned char *c, size_t clen, const unsigned char *ad,
		size_t adlen, const unsigned char *nonce,
		const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES]);

	void        crypto_aead_det_xchacha20_keygen (unsigned char
		k[crypto_aead_det_xchacha20_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
