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

#include <sodium.h>
#include <string.h>

#include "crypto_aead_det_xchacha20.h"

static void
s2v_dbl256 (unsigned char d[32])
{
	unsigned char t[32];
	unsigned char mask;
	size_t      i;

	memcpy (t, d, 32);
	for (i = 0; i < 32; i++)
	{
		t[i] = (unsigned char) (t[i] << 1);
	}
	for (i = 31; i != 0; i--)
	{
		t[i - 1] |= d[i] >> 7;
	}
	mask = ~((d[0] >> 7) - 1);
	t[30] ^= (0x04 & mask);
	t[31] ^= (0x25 & mask);
	memcpy (d, t, 32);
}

static inline void
s2v_xor (unsigned char *d, const unsigned char *h, size_t len)
{
	size_t      i;

	for (i = 0; i < len; i++)
	{
		d[i] ^= h[i];
	}
}

static void
s2v (unsigned char iv[crypto_aead_det_xchacha20_ABYTES],
	const unsigned char *m, size_t mlen, const unsigned char *ad, size_t adlen,
	const unsigned char *nonce, size_t noncelen, const unsigned char ka[32])
{
	static const unsigned char zero[crypto_aead_det_xchacha20_ABYTES] = { 0 };
	crypto_generichash_state st;
	unsigned char d[32];

	crypto_generichash (d, sizeof d, zero, sizeof zero, ka, sizeof d);

	if (ad != NULL && adlen > 0)
	{
		s2v_dbl256 (d);
		crypto_generichash (iv, crypto_aead_det_xchacha20_ABYTES, ad, adlen,
			ka, 32);
		s2v_xor (d, iv, sizeof d);
	}
	if (nonce != NULL && noncelen > 0)
	{
		s2v_dbl256 (d);
		crypto_generichash (iv, crypto_aead_det_xchacha20_ABYTES, nonce,
			noncelen, ka, 32);
		s2v_xor (d, iv, sizeof d);
	}

	crypto_generichash_init (&st, ka, 32, crypto_aead_det_xchacha20_ABYTES);
	if (mlen >= crypto_aead_det_xchacha20_ABYTES)
	{
		crypto_generichash_update (&st, m,
			mlen - crypto_aead_det_xchacha20_ABYTES);
		s2v_xor (d, &m[mlen - crypto_aead_det_xchacha20_ABYTES],
			crypto_aead_det_xchacha20_KEYBYTES);
	}
	else
	{
		s2v_dbl256 (d);
		s2v_xor (d, m, mlen);
		d[mlen] ^= 0x80;
	}
	crypto_generichash_update (&st, d, sizeof d);
	crypto_generichash_final (&st, iv, crypto_aead_det_xchacha20_ABYTES);
}

int
crypto_aead_det_xchacha20_encrypt_detached (unsigned char *c,
	unsigned char mac[crypto_aead_det_xchacha20_ABYTES],
	const unsigned char *m, size_t mlen, const unsigned char *ad, size_t adlen,
	const unsigned char *nonce,
	const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES])
{
	unsigned char subkeys[64], *ka = &subkeys[0], *ke = &subkeys[32];

	crypto_generichash (subkeys, sizeof subkeys, NULL, 0, k,
		crypto_aead_det_xchacha20_KEYBYTES);
	s2v (mac, m, mlen, ad, adlen, nonce, crypto_aead_det_xchacha20_NONCEBYTES,
		ka);
	crypto_stream_xchacha20_xor (c, m, mlen, mac, ke);

	return 0;
}

int
crypto_aead_det_xchacha20_decrypt_detached (unsigned char *m,
	const unsigned char *c, size_t clen,
	const unsigned char mac[crypto_aead_det_xchacha20_ABYTES],
	const unsigned char *ad, size_t adlen, const unsigned char *nonce,
	const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES])
{
	unsigned char subkeys[64], *ka = &subkeys[0], *ke = &subkeys[32];
	unsigned char computed_mac[crypto_aead_det_xchacha20_ABYTES];
	const size_t mlen = clen;

	crypto_generichash (subkeys, sizeof subkeys, NULL, 0, k,
		crypto_aead_det_xchacha20_KEYBYTES);
	crypto_stream_xchacha20_xor (m, c, clen, mac, ke);
	s2v (computed_mac, m, mlen, ad, adlen, nonce,
		crypto_aead_det_xchacha20_NONCEBYTES, ka);
	if (sodium_memcmp (mac, computed_mac,
			crypto_aead_det_xchacha20_ABYTES) != 0)
	{
		memset (m, 0, mlen);
		return -1;
	}
	return 0;
}

int
crypto_aead_det_xchacha20_encrypt (unsigned char *c, const unsigned char *m,
	size_t mlen, const unsigned char *ad, size_t adlen,
	const unsigned char *nonce,
	const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES])
{
	return crypto_aead_det_xchacha20_encrypt_detached (c, c + mlen, m, mlen,
		ad, adlen, nonce, k);
}

int
crypto_aead_det_xchacha20_decrypt (unsigned char *m, const unsigned char *c,
	size_t clen, const unsigned char *ad, size_t adlen,
	const unsigned char *nonce,
	const unsigned char k[crypto_aead_det_xchacha20_KEYBYTES])
{
	size_t      mlen;

	if (clen < crypto_aead_det_xchacha20_ABYTES)
	{
		return -1;
	}
	mlen = clen - crypto_aead_det_xchacha20_ABYTES;

	return crypto_aead_det_xchacha20_decrypt_detached (m, c, mlen, c + mlen,
		ad, adlen, nonce, k);
}

void
crypto_aead_det_xchacha20_keygen (unsigned char
	k[crypto_aead_det_xchacha20_KEYBYTES])
{
	randombytes_buf (k, crypto_aead_det_xchacha20_KEYBYTES);
}
