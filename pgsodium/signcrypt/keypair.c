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
