#include "pgsodium.h"

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
