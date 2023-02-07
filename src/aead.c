#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_keygen);
Datum
pgsodium_crypto_aead_ietf_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size =
		VARHDRSZ + crypto_aead_chacha20poly1305_IETF_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_aead_chacha20poly1305_ietf_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_noncegen);
Datum
pgsodium_crypto_aead_ietf_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size =
		VARHDRSZ + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result),
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_encrypt);
Datum
pgsodium_crypto_aead_ietf_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *nonce;
	bytea      *key;
	unsigned long long result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_PP (2);
	key = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) !=
		crypto_aead_chacha20poly1305_IETF_KEYBYTES, "%s: invalid key");

	result_size = VARSIZE_ANY_EXHDR (message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);
	crypto_aead_chacha20poly1305_ietf_encrypt (
		PGSODIUM_UCHARDATA (result),
		&result_size,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		NULL,
		PGSODIUM_UCHARDATA_ANY (nonce),
		PGSODIUM_UCHARDATA_ANY (key));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_decrypt);
Datum
pgsodium_crypto_aead_ietf_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	bytea      *nonce;
	bytea      *key;
	size_t      ciphertext_len;
	unsigned long long result_size;
	bytea      *result;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_PP (2);
	key = PG_GETARG_BYTEA_PP (3);

	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
		crypto_aead_chacha20poly1305_IETF_ABYTES, "%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	ERRORIF (VARSIZE_ANY_EXHDR (key) !=
		crypto_aead_chacha20poly1305_IETF_KEYBYTES, "%s: invalid key");

	ciphertext_len = VARSIZE_ANY_EXHDR (ciphertext);
	result = _pgsodium_zalloc_bytea (
		ciphertext_len + VARHDRSZ - crypto_aead_chacha20poly1305_IETF_ABYTES);

	success =
		crypto_aead_chacha20poly1305_ietf_decrypt (
			PGSODIUM_UCHARDATA (result),
			&result_size,
			NULL,
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			ciphertext_len,
			associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
			associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
			PGSODIUM_UCHARDATA_ANY (nonce),
			PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_encrypt_by_id);
Datum
pgsodium_crypto_aead_ietf_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *nonce;
	unsigned long long key_id;
	bytea      *context;
	unsigned long long result_size;
	bytea      *result;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_P (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_P (2);
	key_id = PG_GETARG_INT64 (3);
	context = PG_GETARG_BYTEA_P (4);

	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	key =
		pgsodium_derive_helper (key_id,
		crypto_aead_chacha20poly1305_IETF_KEYBYTES, context);
	result_size =
		VARSIZE_ANY (message) + crypto_aead_chacha20poly1305_IETF_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_aead_chacha20poly1305_ietf_encrypt (PGSODIUM_UCHARDATA (result),
		&result_size,
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		NULL, PGSODIUM_UCHARDATA (nonce), PGSODIUM_UCHARDATA (key));
	SET_VARSIZE (result,
		VARHDRSZ + result_size + crypto_aead_chacha20poly1305_IETF_ABYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_ietf_decrypt_by_id);
Datum
pgsodium_crypto_aead_ietf_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	bytea      *nonce;
	unsigned long long key_id;
	bytea      *context;
	size_t      ciphertext_len;
	unsigned long long result_size;
	bytea      *result;
	bytea      *key;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: nonce cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: key context cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_P (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	nonce = PG_GETARG_BYTEA_P (2);
	key_id = PG_GETARG_INT64 (3);
	context = PG_GETARG_BYTEA_P (4);

	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
		crypto_aead_chacha20poly1305_IETF_ABYTES, "%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES, "%s: invalid nonce");
	key =
		pgsodium_derive_helper (key_id,
		crypto_aead_chacha20poly1305_IETF_KEYBYTES, context);

	ciphertext_len = VARSIZE_ANY_EXHDR (ciphertext) -
		crypto_aead_chacha20poly1305_IETF_ABYTES;
	result = _pgsodium_zalloc_bytea (ciphertext_len);

	success =
		crypto_aead_chacha20poly1305_ietf_decrypt (
			PGSODIUM_UCHARDATA (result),
			&result_size,
			NULL,
			PGSODIUM_UCHARDATA (ciphertext), ciphertext_len,
			associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
			associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
			PGSODIUM_UCHARDATA (nonce),
			PGSODIUM_UCHARDATA (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	SET_VARSIZE (result, VARHDRSZ + result_size);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_keygen);
Datum
pgsodium_crypto_aead_det_keygen (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_aead_det_xchacha20_KEYBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	crypto_aead_det_xchacha20_keygen (PGSODIUM_UCHARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_noncegen);
Datum
pgsodium_crypto_aead_det_noncegen (PG_FUNCTION_ARGS)
{
	int         result_size = VARHDRSZ + crypto_aead_det_xchacha20_NONCEBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_aead_det_xchacha20_NONCEBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_encrypt);
Datum
pgsodium_crypto_aead_det_encrypt (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	bytea      *key;
	bytea      *nonce;
	size_t      result_size;
	bytea      *result;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);

	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_aead_det_xchacha20_KEYBYTES,
		"%s: invalid key");
	if (!PG_ARGISNULL (3))
	{
		nonce = PG_GETARG_BYTEA_PP (3);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}
	result_size =
		VARSIZE_ANY_EXHDR (message) + crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);
	success = crypto_aead_det_xchacha20_encrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: crypto_aead_det_xchacha20_encrypt failed");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_decrypt);
Datum
pgsodium_crypto_aead_det_decrypt (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	bytea      *key;
	size_t      result_len;
	bytea      *result, *nonce;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: ciphertext cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);
	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
		crypto_aead_det_xchacha20_ABYTES, "%s: invalid message");
	ERRORIF (VARSIZE_ANY_EXHDR (key) != crypto_aead_det_xchacha20_KEYBYTES,
		"%s: invalid key");
	result_len =
		VARSIZE_ANY_EXHDR (ciphertext) - crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_len + VARHDRSZ);
	if (!PG_ARGISNULL (3))
	{
		nonce = PG_GETARG_BYTEA_P (3);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}
	success = crypto_aead_det_xchacha20_decrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_encrypt_by_id);
Datum
pgsodium_crypto_aead_det_encrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *associated;
	unsigned long long key_id;
	bytea      *context;
	bytea      *key, *nonce;
	size_t      result_size;
	bytea      *result;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);

	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);

	if (!PG_ARGISNULL (4))
	{
		nonce = PG_GETARG_BYTEA_PP (4);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}

	result_size =
		VARSIZE_ANY_EXHDR (message) + crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_size + VARHDRSZ);

	key =
		pgsodium_derive_helper (key_id, crypto_aead_det_xchacha20_KEYBYTES,
		context);

	success = crypto_aead_det_xchacha20_encrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: failed");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_aead_det_decrypt_by_id);
Datum
pgsodium_crypto_aead_det_decrypt_by_id (PG_FUNCTION_ARGS)
{
	bytea      *ciphertext;
	bytea      *associated;
	unsigned long long key_id;
	bytea      *context;
	size_t      result_len;
	bytea      *key, *result, *nonce;
	int         success;


	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key id cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: key context cannot be NULL");

	ciphertext = PG_GETARG_BYTEA_PP (0);

	if (!PG_ARGISNULL (1))
	{
		associated = PG_GETARG_BYTEA_PP (1);
	}
	else
	{
		associated = NULL;
	}

	key_id = PG_GETARG_INT64 (2);
	context = PG_GETARG_BYTEA_PP (3);

	if (!PG_ARGISNULL (4))
	{
		nonce = PG_GETARG_BYTEA_PP (4);
		ERRORIF (VARSIZE_ANY_EXHDR (nonce) !=
			crypto_aead_det_xchacha20_NONCEBYTES, "%s: invalid nonce");
	}
	else
	{
		nonce = NULL;
	}
	ERRORIF (VARSIZE_ANY_EXHDR (ciphertext) <=
		crypto_aead_det_xchacha20_ABYTES, "%s: invalid message");
	result_len =
		VARSIZE_ANY_EXHDR (ciphertext) - crypto_aead_det_xchacha20_ABYTES;
	result = _pgsodium_zalloc_bytea (result_len + VARHDRSZ);
	key =
		pgsodium_derive_helper (key_id, crypto_aead_det_xchacha20_KEYBYTES,
		context);

	success = crypto_aead_det_xchacha20_decrypt (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext),
		associated != NULL ? PGSODIUM_UCHARDATA_ANY (associated) : NULL,
		associated != NULL ? VARSIZE_ANY_EXHDR (associated) : 0,
		nonce != NULL ? PGSODIUM_UCHARDATA_ANY (nonce) : NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	ERRORIF (success != 0, "%s: invalid ciphertext");
	PG_RETURN_BYTEA_P (result);
}
