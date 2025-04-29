#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_keypair);
Datum
pgsodium_crypto_sign_keypair (PG_FUNCTION_ARGS)
{
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *publickey;
	bytea      *secretkey;
	size_t      public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t      secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea (public_size);
	secretkey = _pgsodium_zalloc_bytea (secret_size);
	crypto_sign_keypair (
		PGSODIUM_UCHARDATA (publickey),
		PGSODIUM_UCHARDATA (secretkey));
	values[0] = PointerGetDatum (publickey);
	values[1] = PointerGetDatum (secretkey);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}
