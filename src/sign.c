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

PGDLLEXPORT PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_new_seed);
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
	bytea      *seed;
	size_t      public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t      secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;

	ERRORIF (PG_ARGISNULL (0), "%s: seed cannot be NULL");
	seed = PG_GETARG_BYTEA_PP (0);

	ERRORIF (VARSIZE_ANY_EXHDR (seed) != crypto_sign_SEEDBYTES,
		"%s: invalid seed");

	if (get_call_result_type (fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport (ERROR,
			(errcode (ERRCODE_FEATURE_NOT_SUPPORTED),
				errmsg ("function returning record called in context "
					"that cannot accept type record")));

	publickey = _pgsodium_zalloc_bytea (public_size);
	secretkey = _pgsodium_zalloc_bytea (secret_size);
	crypto_sign_seed_keypair (
		PGSODIUM_UCHARDATA (publickey),
		PGSODIUM_UCHARDATA (secretkey),
		PGSODIUM_UCHARDATA_ANY (seed));

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
	bytea      *message;
	bytea      *secretkey;
	unsigned long long signed_message_len;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	secretkey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	result_size = crypto_sign_BYTES + VARSIZE_ANY (message);
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign (
		PGSODIUM_UCHARDATA (result),
		&signed_message_len,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_open);
Datum
pgsodium_crypto_sign_open (PG_FUNCTION_ARGS)
{
	int         success;
	unsigned long long unsigned_message_len;
	bytea      *message;
	bytea      *publickey;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: publickey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	publickey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	ERRORIF (VARSIZE_ANY_EXHDR (message) <= crypto_sign_BYTES,
		"%s: invalid message");

	result_size = VARSIZE_ANY (message) - crypto_sign_BYTES;
	result = _pgsodium_zalloc_bytea (result_size);
	success = crypto_sign_open (
		PGSODIUM_UCHARDATA (result),
		&unsigned_message_len,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (publickey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_detached);
Datum
pgsodium_crypto_sign_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *message;
	bytea      *secretkey;
	size_t      sig_size = crypto_sign_BYTES;
	size_t      result_size = VARHDRSZ + sig_size;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: secretkey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	secretkey = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (secretkey) != crypto_sign_SECRETKEYBYTES,
		"%s: invalid secret key");
	success = crypto_sign_detached (
		PGSODIUM_UCHARDATA (result),
		NULL,
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (secretkey));
	ERRORIF (success != 0, "%s: invalid message");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_verify_detached);
Datum
pgsodium_crypto_sign_verify_detached (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *sig;
	bytea      *message;
	bytea      *publickey;

	ERRORIF (PG_ARGISNULL (0), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: publickey cannot be NULL");

	sig       = PG_GETARG_BYTEA_PP (0);
	message   = PG_GETARG_BYTEA_PP (1);
	publickey = PG_GETARG_BYTEA_PP (2);

	ERRORIF (VARSIZE_ANY_EXHDR (publickey) != crypto_sign_PUBLICKEYBYTES,
		"%s: invalid public key");
	success = crypto_sign_verify_detached (
		PGSODIUM_UCHARDATA_ANY (sig),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (publickey));
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
	bytea      *state;
	bytea      *msg_part;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: message part cannot be NULL");

	state = PG_GETARG_BYTEA_P_COPY (0);	// input state
	msg_part = PG_GETARG_BYTEA_PP (1);

	crypto_sign_update (
		(crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA_ANY (msg_part),
		VARSIZE_ANY_EXHDR (msg_part));
	PG_RETURN_BYTEA_P (state);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_final_create);
Datum
pgsodium_crypto_sign_final_create (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *state;
	bytea      *key;
	size_t      sig_size = crypto_sign_BYTES;
	size_t      result_size = VARHDRSZ + sig_size;
	bytea      *result = _pgsodium_zalloc_bytea (result_size);

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: key cannot be NULL");

	state = PG_GETARG_BYTEA_P_COPY (0);
	key = PG_GETARG_BYTEA_PP (1);

	success = crypto_sign_final_create (
		(crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA_ANY (result),
		NULL,
		PGSODIUM_UCHARDATA_ANY (key));
	pfree (state);
	ERRORIF (success != 0, "%s: unable to complete signature");
	PG_RETURN_BYTEA_P (result);
}

PG_FUNCTION_INFO_V1 (pgsodium_crypto_sign_final_verify);
Datum
pgsodium_crypto_sign_final_verify (PG_FUNCTION_ARGS)
{
	int         success;
	bytea      *state;
	bytea      *sig;
	bytea      *key;

	ERRORIF (PG_ARGISNULL (0), "%s: state cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: signature cannot be NULL");
	ERRORIF (PG_ARGISNULL (2), "%s: key cannot be NULL");

	state = PG_GETARG_BYTEA_P_COPY (0);
	sig = PG_GETARG_BYTEA_PP (1);
	key = PG_GETARG_BYTEA_PP (2);

	success = crypto_sign_final_verify (
		(crypto_sign_state *) VARDATA (state),
		PGSODIUM_UCHARDATA_ANY (sig),
		PGSODIUM_UCHARDATA_ANY (key));
	pfree (state);
	PG_RETURN_BOOL (success == 0);
}
