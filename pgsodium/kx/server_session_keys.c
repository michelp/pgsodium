#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_kx_server_session_keys);
Datum
pgsodium_crypto_kx_server_session_keys (PG_FUNCTION_ARGS)
{
	int         success;
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *rx;
	bytea      *tx;
	bytea      *server_pk;
	bytea      *server_sk;
	bytea      *client_pk;
	size_t      rx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
	size_t      tx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;

	ERRORIF (PG_ARGISNULL (0), "%s: server publickey cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: server secretkey cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: client publickey cannot be NULL");

	server_pk = PG_GETARG_BYTEA_PP (0);
	server_sk = PG_GETARG_BYTEA_PP (1);
	client_pk = PG_GETARG_BYTEA_PP (2);

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));
	ERRORIF (VARSIZE_ANY_EXHDR (server_pk) != crypto_kx_PUBLICKEYBYTES,
		"%s: bad server public key");
	ERRORIF (VARSIZE_ANY_EXHDR (server_sk) != crypto_kx_SECRETKEYBYTES,
		"%s: bad server secret key");
	ERRORIF (VARSIZE_ANY_EXHDR (client_pk) != crypto_kx_PUBLICKEYBYTES,
		"%s: bad client public key");
	rx = _pgsodium_zalloc_bytea (rx_size);
	tx = _pgsodium_zalloc_bytea (tx_size);
	success = crypto_kx_server_session_keys (
		PGSODIUM_UCHARDATA (rx),
		PGSODIUM_UCHARDATA (tx),
		PGSODIUM_UCHARDATA_ANY (server_pk),
		PGSODIUM_UCHARDATA_ANY (server_sk),
		PGSODIUM_UCHARDATA_ANY (client_pk));
	ERRORIF (success != 0, "%s: invalid message");
	values[0] = PointerGetDatum (rx);
	values[1] = PointerGetDatum (tx);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}
