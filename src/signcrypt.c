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
	crypto_signcrypt_tbsbr_keygen (PGSODIUM_UCHARDATA (publickey),
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
	bytea      *sender = PG_GETARG_BYTEA_P (0);
	bytea      *recipient = PG_GETARG_BYTEA_P (1);
	bytea      *sender_sk = PG_GETARG_BYTEA_P (2);
	bytea      *recipient_pk = PG_GETARG_BYTEA_P (3);
	bytea      *additional = PG_GETARG_BYTEA_P (4);

	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *state, *shared_key;
	int         success;

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
		crypto_signcrypt_tbsbr_sign_before (PGSODIUM_UCHARDATA (state),
		PGSODIUM_UCHARDATA (shared_key),
		PGSODIUM_UCHARDATA (sender),
		VARSIZE_ANY_EXHDR (sender),
		PGSODIUM_UCHARDATA (recipient),
		VARSIZE_ANY_EXHDR (recipient),
		PGSODIUM_UCHARDATA (additional),
		VARSIZE_ANY_EXHDR (additional),
		PGSODIUM_UCHARDATA (sender_sk),
		PGSODIUM_UCHARDATA (recipient_pk), NULL, 0);

	ERRORIF (success != 0, "%s: sign_before failed");
	values[0] = PointerGetDatum (state);
	values[1] = PointerGetDatum (shared_key);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_sign_after);
Datum
pgsodium_crypto_signcrypt_sign_after (PG_FUNCTION_ARGS)
{
	bytea      *state = PG_GETARG_BYTEA_P (0);
	bytea      *sender_sk = PG_GETARG_BYTEA_P (1);
	bytea      *ciphertext = PG_GETARG_BYTEA_P (2);
	bytea      *signature =
		_pgsodium_zalloc_bytea (crypto_signcrypt_tbsbr_SIGNBYTES + VARHDRSZ);
	int         success;

	success = crypto_signcrypt_tbsbr_sign_after (PGSODIUM_UCHARDATA (state),
		PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA (sender_sk),
		PGSODIUM_UCHARDATA (ciphertext), VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: sign_after failed");
	PG_RETURN_BYTEA_P (signature);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_before);
Datum
pgsodium_crypto_signcrypt_verify_before (PG_FUNCTION_ARGS)
{
	bytea      *signature = PG_GETARG_BYTEA_P (0);
	bytea      *sender = PG_GETARG_BYTEA_P (1);
	bytea      *recipient = PG_GETARG_BYTEA_P (2);
	bytea      *additional = PG_GETARG_BYTEA_P (3);
	bytea      *sender_pk = PG_GETARG_BYTEA_P (4);
	bytea      *recipient_sk = PG_GETARG_BYTEA_P (5);

	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *state, *shared_key;
	int         success;

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
		crypto_signcrypt_tbsbr_verify_before (PGSODIUM_UCHARDATA (state),
		PGSODIUM_UCHARDATA (shared_key),
		PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA (sender),
		VARSIZE_ANY_EXHDR (sender),
		PGSODIUM_UCHARDATA (recipient),
		VARSIZE_ANY_EXHDR (recipient),
		PGSODIUM_UCHARDATA (additional),
		VARSIZE_ANY_EXHDR (additional),
		PGSODIUM_UCHARDATA (sender_pk), PGSODIUM_UCHARDATA (recipient_sk));
	ERRORIF (success != 0, "%s: verify_before failed");
	values[0] = PointerGetDatum (state);
	values[1] = PointerGetDatum (shared_key);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_after);
Datum
pgsodium_crypto_signcrypt_verify_after (PG_FUNCTION_ARGS)
{
	bytea      *state = PG_GETARG_BYTEA_P (0);
	bytea      *signature = PG_GETARG_BYTEA_P (1);
	bytea      *sender_pk = PG_GETARG_BYTEA_P (2);
	bytea      *ciphertext = PG_GETARG_BYTEA_P (3);
	int         success;

	success =
		crypto_signcrypt_tbsbr_verify_after (PGSODIUM_UCHARDATA (state),
		PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA (sender_pk),
		PGSODIUM_UCHARDATA (ciphertext), VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_after failed");
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_signcrypt_verify_public);
Datum
pgsodium_crypto_signcrypt_verify_public (PG_FUNCTION_ARGS)
{
	bytea      *signature = PG_GETARG_BYTEA_P (0);
	bytea      *sender = PG_GETARG_BYTEA_P (1);
	bytea      *recipient = PG_GETARG_BYTEA_P (2);
	bytea      *additional = PG_GETARG_BYTEA_P (3);
	bytea      *sender_pk = PG_GETARG_BYTEA_P (4);
	bytea      *ciphertext = PG_GETARG_BYTEA_P (5);
	int         success;

	success =
		crypto_signcrypt_tbsr_verify_public (PGSODIUM_UCHARDATA (signature),
		PGSODIUM_UCHARDATA (sender),
		VARSIZE_ANY_EXHDR (sender),
		PGSODIUM_UCHARDATA (recipient),
		VARSIZE_ANY_EXHDR (recipient),
		PGSODIUM_UCHARDATA (additional),
		VARSIZE_ANY_EXHDR (additional),
		PGSODIUM_UCHARDATA (sender_pk),
		PGSODIUM_UCHARDATA (ciphertext), VARSIZE_ANY_EXHDR (ciphertext));

	ERRORIF (success != 0, "%s: verify_public failed");
	PG_RETURN_BOOL (success == 0);
}
