/* MIT License */

/* Copyright (c) 2020-2021 Frank Denis */

/* Permission is hereby granted, free of charge, to any person obtaining a copy */
/* of this software and associated documentation files (the "Software"), to deal */
/* in the Software without restriction, including without limitation the rights */
/* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell */
/* copies of the Software, and to permit persons to whom the Software is */
/* furnished to do so, subject to the following conditions: */

/* The above copyright notice and this permission notice shall be included in all */
/* copies or substantial portions of the Software. */

/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR */
/* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, */
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE */
/* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER */
/* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, */
/* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE */
/* SOFTWARE. */

#ifndef signcrypt_tbsbr_H
#define signcrypt_tbsbr_H

#ifdef __cplusplus
extern      "C"
{
#endif

#include <stdlib.h>

#if !defined(__clang__) && !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(X)
#endif

#define crypto_signcrypt_tbsbr_SECRETKEYBYTES 32
#define crypto_signcrypt_tbsbr_PUBLICKEYBYTES 32
#define crypto_signcrypt_tbsbr_SHAREDBYTES 32
#define crypto_signcrypt_tbsbr_SEEDBYTES 64
#define crypto_signcrypt_tbsbr_SIGNBYTES (32 + 32)
#define crypto_signcrypt_tbsbr_STATEBYTES 512

	int         crypto_signcrypt_tbsbr_sign_before (unsigned char
		st[crypto_signcrypt_tbsbr_STATEBYTES],
		unsigned char shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES],
		const unsigned char *sender_id, size_t sender_id_len,
		const unsigned char *recipient_id, size_t recipient_id_len,
		const unsigned char *info, size_t info_len,
		const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
		const unsigned char
		recipient_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		const unsigned char *m, size_t m_len)
		__attribute__((warn_unused_result));

	int         crypto_signcrypt_tbsbr_sign_after (unsigned char
		st[crypto_signcrypt_tbsbr_STATEBYTES],
		unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
		const unsigned char sender_sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
		const unsigned char *c, size_t c_len)
		__attribute__((warn_unused_result));

	int         crypto_signcrypt_tbsbr_verify_before (unsigned char
		st[crypto_signcrypt_tbsbr_STATEBYTES],
		unsigned char shared_key[crypto_signcrypt_tbsbr_SHAREDBYTES],
		const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
		const unsigned char *sender_id, size_t sender_id_len,
		const unsigned char *recipient_id, size_t recipient_id_len,
		const unsigned char *info, size_t info_len,
		const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		const unsigned char
		recipient_sk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES])
		__attribute__((warn_unused_result));

	int         crypto_signcrypt_tbsbr_verify_after (unsigned char
		st[crypto_signcrypt_tbsbr_STATEBYTES],
		const unsigned char sig[crypto_signcrypt_tbsbr_SIGNBYTES],
		const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		const unsigned char *c, size_t c_len)
		__attribute__((warn_unused_result));

	int         crypto_signcrypt_tbsr_verify_public (const unsigned char
		sig[crypto_signcrypt_tbsbr_SIGNBYTES], const unsigned char *sender_id,
		size_t sender_id_len, const unsigned char *recipient_id,
		size_t recipient_id_len, const unsigned char *info, size_t info_len,
		const unsigned char sender_pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		const unsigned char *c, size_t c_len)
		__attribute__((warn_unused_result));

	void        crypto_signcrypt_tbsbr_keygen (unsigned char
		pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES]);

	void        crypto_signcrypt_tbsbr_seed_keygen (unsigned char
		pk[crypto_signcrypt_tbsbr_PUBLICKEYBYTES],
		unsigned char sk[crypto_signcrypt_tbsbr_SECRETKEYBYTES],
		const unsigned char seed[crypto_signcrypt_tbsbr_SEEDBYTES]);

#ifdef __cplusplus
}
#endif

#endif
