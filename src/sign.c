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
	crypto_sign_keypair (PGSODIUM_UCHARDATA (publickey),
		PGSODIUM_UCHARDATA (secretkey));
	values[0] = PointerGetDatum (publickey);
	values[1] = PointerGetDatum (secretkey);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_new_seed);
Datum
pgsodium_crypto_sign_new_seed (PG_FUNCTION_ARGS)
{
	size_t      result_size = VARHDRSZ + crypto_sign_SEEDBYTES;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	randombytes_buf (VARDATA (result), crypto_sign_SEEDBYTES);
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_seed_keypair);
Datum
pgsodium_crypto_sign_seed_keypair (PG_FUNCTION_ARGS)
{
	TupleDesc   tupdesc;
	Datum       values[2];
	bool        nulls[2] = { false, false };
	HeapTuple   tuple;
	Datum       result;
	bytea      *publickey;
	bytea      *secretkey;
	bytea      *seed = PG_GETARG_BYTEA_P (0);
	size_t      public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t      secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;
	ERRORIF (VARSIZE_ANY_EXHDR (seed) != crypto_sign_SEEDBYTES,
		"%s: invalid seed");

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));

	publickey = _pgsodium_zalloc_bytea (public_size);
	secretkey = _pgsodium_zalloc_bytea (secret_size);
	crypto_sign_seed_keypair (PGSODIUM_UCHARDATA (publickey),
		PGSODIUM_UCHARDATA (secretkey), PGSODIUM_UCHARDATA (seed));

	values[0] = PointerGetDatum (publickey);
	values[1] = PointerGetDatum (secretkey);
	tuple = heap_form_tuple (tupdesc, values, nulls);
	result = HeapTupleGetDatum (tuple);
	return result;
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign);
Datum
pgsodium_crypto_sign (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message = PG_GETARG_BYTEA_P (0);
	bytea      *secretkey = PG_GETARG_BYTEA_P (1);
	unsigned long long signed_message_len;
	size_t      message_size;
	size_t      result_size;
	bytea      *result;
	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	message_size = crypto_sign_BYTES + VARSIZE_ANY_EXHDR (message);
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign (PGSODIUM_UCHARDATA (result),
		&signed_message_len,
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message), PGSODIUM_UCHARDATA (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_open);
Datum
pgsodium_crypto_sign_open (PG_FUNCTION_ARGS)
{
	int         success;
	unsigned long long unsigned_message_len;
	bytea      *message = PG_GETARG_BYTEA_P (0);
	bytea      *publickey = PG_GETARG_BYTEA_P (1);
	size_t      message_size;
	size_t      result_size;
	bytea      *result;

	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_sign_BYTES,
		"%s: invalid message");

	message_size = VARSIZE_ANY_EXHDR (message) - crypto_sign_BYTES;
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign_open (PGSODIUM_UCHARDATA (result),
		&unsigned_message_len,
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message), PGSODIUM_UCHARDATA (publickey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_detached);
Datum
pgsodium_crypto_sign_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message = PG_GETARG_BYTEA_P (0);
	bytea      *secretkey = PG_GETARG_BYTEA_P (1);
	size_t      sig_size = crypto_sign_BYTES;
	size_t      result_size = VARHDRSZ + sig_size;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);
	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	success = crypto_sign_detached (PGSODIUM_UCHARDATA (result),
		NULL,
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message), PGSODIUM_UCHARDATA (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_verify_detached);
Datum
pgsodium_crypto_sign_verify_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *sig = PG_GETARG_BYTEA_P (0);
	bytea      *message = PG_GETARG_BYTEA_P (1);
	bytea      *publickey = PG_GETARG_BYTEA_P (2);
	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	success = crypto_sign_verify_detached (PGSODIUM_UCHARDATA (sig),
		PGSODIUM_UCHARDATA (message),
		VARSIZE_ANY_EXHDR (message), PGSODIUM_UCHARDATA (publickey));
	PG_RETURN_BOOL (success == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_init);
Datum
pgsodium_crypto_sign_init (PG_FUNCTION_ARGS)
{
	bytea      *result =
		_pgsodium_zalloc_bytea (VARHDRSZ + sizeof (crypto_sign_state));
	crypto_sign_init ((crypto_sign_state *) VARDATA (result));
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_update);
Datum
pgsodium_crypto_sign_update (PG_FUNCTION_ARGS)
{
	bytea      *state = PG_GETARG_BYTEA_P_COPY (0);	// input state
	bytea      *msg_part = PG_GETARG_BYTEA_P (1);

	crypto_sign_update ((crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA (msg_part), VARSIZE_ANY_EXHDR (msg_part));
	PG_RETURN_BYTEA_P (state);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_final_create);
Datum
pgsodium_crypto_sign_final_create (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *state = PG_GETARG_BYTEA_P_COPY (0);
	bytea      *key = PG_GETARG_BYTEA_P (1);
	size_t      sig_size = crypto_sign_BYTES;
	size_t      result_size = VARHDRSZ + sig_size;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);

	success = crypto_sign_final_create ((crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA (result), NULL, PGSODIUM_UCHARDATA (key));
	pfree (state);

	ERRORIF (success != 0, "%s: unable to complete signature");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_final_verify);
Datum
pgsodium_crypto_sign_final_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *state = PG_GETARG_BYTEA_P_COPY (0);
	bytea      *sig = PG_GETARG_BYTEA_P (1);	// why doesn't _P work here?
	bytea      *key = PG_GETARG_BYTEA_P (2);

	success = crypto_sign_final_verify ((crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA (sig), PGSODIUM_UCHARDATA (key));
	pfree (state);
	PG_RETURN_BOOL (success == 0);
}
