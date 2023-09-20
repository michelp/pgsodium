#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_keypair);
Datum
pgsodium_crypto_signcrypt_keypair (PG_FUNCTION_ARGS)
{
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *publickey;
	bytea      *secretkey;

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_PUBLICKEYBYTES +
		VARHDRSZ);
	secretkey = _pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SECRETKEYBYTES +
		VARHDRSZ);
	crypto_signcrypt_tbsbr_keygen (
		PGSODIUM_UCHARDATA (publickey),
		PGSODIUM_UCHARDATA (secretkey));
	values[0] = PointerGetDatum (publickey);
	values[1] = PointerGetDatum (secretkey);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_sign_before);
Datum
pgsodium_crypto_signcrypt_sign_before (PG_FUNCTION_ARGS)
{
	bytea      *sender;
	bytea      *recipient;
	bytea      *sender_sk;
	bytea      *recipient_pk;
	bytea      *associated;
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *state, *shared_key;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: sender cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: recipient cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: sender secretkey cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: recipient publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: associated cannot be NULL");

	sender = PG_GETARG_BYTEA_PP (0);
	recipient = PG_GETARG_BYTEA_PP (1);
	sender_sk = PG_GETARG_BYTEA_PP (2);
	recipient_pk = PG_GETARG_BYTEA_PP (3);
	associated = PG_GETARG_BYTEA_PP (4);

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));

	state =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_STATEBYTES + VARHDRSZ);
	shared_key =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SECRETKEYBYTES +
		VARHDRSZ);

	success =
		crypto_signcrypt_tbsbr_sign_before (
			PGSODIUM_UCHARDATA (state),
			PGSODIUM_UCHARDATA (shared_key),
			PGSODIUM_UCHARDATA_ANY (sender),
			VARSIZE_ANY_EXHDR (sender),
			PGSODIUM_UCHARDATA_ANY (recipient),
			VARSIZE_ANY_EXHDR (recipient),
			PGSODIUM_UCHARDATA_ANY (associated),
			VARSIZE_ANY_EXHDR (associated),
			PGSODIUM_UCHARDATA_ANY (sender_sk),
			PGSODIUM_UCHARDATA_ANY (recipient_pk),
			NULL,
			0);

	ERRORIF (success != 0, "%s: sign_before failed");
	values[0] = PointerGetDatum (state);
	values[1] = PointerGetDatum (shared_key);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_sign_after);
Datum
pgsodium_crypto_signcrypt_sign_after (PG_FUNCTION_ARGS)
{
	bytea      *state;
	bytea      *sender_sk;
	bytea      *ciphertext;
	bytea      *signature =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SIGNBYTES + VARHDRSZ);
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: sender secretkey cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: ciphertext cannot be NULL");

	state = PG_GETARG_BYTEA_PP (0);
	sender_sk = PG_GETARG_BYTEA_PP (1);
	ciphertext = PG_GETARG_BYTEA_PP (2);

	success = crypto_signcrypt_tbsbr_sign_after (
		PGSODIUM_UCHARDATA_ANY (state),
		PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA_ANY (sender_sk),
		PGSODIUM_UCHARDATA_ANY (ciphertext),
		VARSIZE_ANY_EXHDR (ciphertext));
	ERRORIF (success != 0, "%s: sign_after failed");
	PG_RETURN_BYTEA_P (signature);
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_before);
Datum
pgsodium_crypto_signcrypt_verify_before (PG_FUNCTION_ARGS)
{
	bytea      *signature;
	bytea      *sender;
	bytea      *recipient;
	bytea      *associated;
	bytea      *sender_pk;
	bytea      *recipient_sk;
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *state, *shared_key;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: sender cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: recipient cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: associated cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: sender publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (5), "%s: recipient secretkey cannot be NULL");

	signature = PG_GETARG_BYTEA_PP (0);
	sender = PG_GETARG_BYTEA_PP (1);
	recipient = PG_GETARG_BYTEA_PP (2);
	associated = PG_GETARG_BYTEA_PP (3);
	sender_pk = PG_GETARG_BYTEA_PP (4);
	recipient_sk = PG_GETARG_BYTEA_PP (5);

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));

	state =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_STATEBYTES + VARHDRSZ);
	shared_key =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SECRETKEYBYTES +
		VARHDRSZ);

	success =
		crypto_signcrypt_tbsbr_verify_before (
			PGSODIUM_UCHARDATA (state),
			PGSODIUM_UCHARDATA (shared_key),
			PGSODIUM_UCHARDATA_ANY (signature),
			PGSODIUM_UCHARDATA_ANY (sender),
			VARSIZE_ANY_EXHDR (sender),
			PGSODIUM_UCHARDATA_ANY (recipient),
			VARSIZE_ANY_EXHDR (recipient),
			PGSODIUM_UCHARDATA_ANY (associated),
			VARSIZE_ANY_EXHDR (associated),
			PGSODIUM_UCHARDATA_ANY (sender_pk),
			PGSODIUM_UCHARDATA_ANY (recipient_sk));
	ERRORIF (success != 0, "%s: verify_before failed");
	values[0] = PointerGetDatum (state);
	values[1] = PointerGetDatum (shared_key);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_after);
Datum
pgsodium_crypto_signcrypt_verify_after (PG_FUNCTION_ARGS)
{
	bytea      *state;
	bytea      *signature;
	bytea      *sender_pk;
	bytea      *ciphertext;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: sender publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: ciphertext cannot be NULL");

	state = PG_GETARG_BYTEA_PP (0);
	signature = PG_GETARG_BYTEA_PP (1);
	sender_pk = PG_GETARG_BYTEA_PP (2);
	ciphertext = PG_GETARG_BYTEA_PP (3);

	success =
		crypto_signcrypt_tbsbr_verify_after (
			PGSODIUM_UCHARDATA_ANY (state),
			PGSODIUM_UCHARDATA_ANY (signature),
			PGSODIUM_UCHARDATA_ANY (sender_pk),
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_after failed");
	PG_RETURN_BOOL (success == 0);
}

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_public);
Datum
pgsodium_crypto_signcrypt_verify_public (PG_FUNCTION_ARGS)
{
	bytea      *signature;
	bytea      *sender;
	bytea      *recipient;
	bytea      *associated;
	bytea      *sender_pk;
	bytea      *ciphertext;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: sender cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: recipient cannot be NULL");
	ERRORIF (PG_ARGISNULL (3), "%s: associated cannot be NULL");
	ERRORIF (PG_ARGISNULL (4), "%s: sender publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (5), "%s: ciphertext cannot be NULL");

	signature = PG_GETARG_BYTEA_PP (0);
	sender = PG_GETARG_BYTEA_PP (1);
	recipient = PG_GETARG_BYTEA_PP (2);
	associated = PG_GETARG_BYTEA_PP (3);
	sender_pk = PG_GETARG_BYTEA_PP (4);
	ciphertext = PG_GETARG_BYTEA_PP (5);

	success =
		crypto_signcrypt_tbsr_verify_public (
			PGSODIUM_UCHARDATA_ANY (signature),
			PGSODIUM_UCHARDATA_ANY (sender),
			VARSIZE_ANY_EXHDR (sender),
			PGSODIUM_UCHARDATA_ANY (recipient),
			VARSIZE_ANY_EXHDR (recipient),
			PGSODIUM_UCHARDATA_ANY (associated),
			VARSIZE_ANY_EXHDR (associated),
			PGSODIUM_UCHARDATA_ANY (sender_pk),
			PGSODIUM_UCHARDATA_ANY (ciphertext),
			VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_public failed");
	PG_RETURN_BOOL (success == 0);
}
