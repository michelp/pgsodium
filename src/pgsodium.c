#include "pgsodium.h"

PG_MODULE_MAGIC;

/* GUC Variables */
static bytea* pgsodium_secret_key = NULL;

PG_FUNCTION_INFO_V1(pgsodium_randombytes_random);
Datum
pgsodium_randombytes_random(PG_FUNCTION_ARGS)
{
	PG_RETURN_UINT32(randombytes_random());
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_uniform);
Datum
pgsodium_randombytes_uniform(PG_FUNCTION_ARGS)
{
	uint32_t upper_bound = PG_GETARG_UINT32(0);
	PG_RETURN_UINT32(randombytes_uniform(upper_bound));
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_buf);
Datum
pgsodium_randombytes_buf(PG_FUNCTION_ARGS)
{
	size_t size = PG_GETARG_UINT32(0);
	size_t result_size = VARHDRSZ + size;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), size);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_new_seed);
Datum
pgsodium_randombytes_new_seed(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + randombytes_SEEDBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), randombytes_SEEDBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_randombytes_buf_deterministic);
Datum
pgsodium_randombytes_buf_deterministic(PG_FUNCTION_ARGS)
{
	size_t size = PG_GETARG_UINT32(0);
	bytea* seed = PG_GETARG_BYTEA_P(1);
	size_t result_size = VARHDRSZ + size;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf_deterministic(
		VARDATA(result),
		size,
		PGSODIUM_UCHARDATA(seed));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_keygen);
Datum
pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_secretbox_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_noncegen);
Datum
pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS)
{
	int result_size = VARHDRSZ + crypto_secretbox_NONCEBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox);
Datum
pgsodium_crypto_secretbox(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* nonce = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	size_t message_size = crypto_secretbox_MACBYTES + VARSIZE_ANY_EXHDR(message);
	size_t result_size = VARHDRSZ + message_size;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_secretbox_easy(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(nonce),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_open);
Datum
pgsodium_crypto_secretbox_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* nonce = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	size_t message_size;
	size_t result_size;
	bytea* result;

	ERRORIF(VARSIZE_ANY_EXHDR(message) <= crypto_secretbox_MACBYTES,
			"invalid message");
	ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_secretbox_NONCEBYTES,
			"invalid nonce");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_secretbox_KEYBYTES,
			"invalid key");

	message_size = VARSIZE_ANY_EXHDR(message) - crypto_secretbox_MACBYTES;
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea(result_size);

	success = crypto_secretbox_open_easy(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(nonce),
		PGSODIUM_UCHARDATA(key));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth);
Datum
pgsodium_crypto_auth(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	int result_size;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "invalid key");
	result_size = VARHDRSZ + crypto_auth_BYTES;
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_verify);
Datum
pgsodium_crypto_auth_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* mac = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(mac) != crypto_auth_BYTES, "invalid mac");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_KEYBYTES, "invalid key");
	success = crypto_auth_verify(
		PGSODIUM_UCHARDATA(mac),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_keygen);
Datum
pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_auth_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash_keygen);
Datum
pgsodium_crypto_generichash_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_generichash_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash);
Datum
pgsodium_crypto_generichash(PG_FUNCTION_ARGS)
{
	bytea* data;
	bytea* result;
	bytea* keyarg;
	unsigned char* key = NULL;
	size_t keylen = 0;
	size_t result_size;
	data = PG_GETARG_BYTEA_P(0);
	if (!PG_ARGISNULL(1))
	{
		keyarg = PG_GETARG_BYTEA_P(1);
		key = PGSODIUM_UCHARDATA(keyarg);
		keylen = VARSIZE_ANY_EXHDR(keyarg);
		ERRORIF(keylen <= crypto_generichash_KEYBYTES_MIN ||
				keylen >= crypto_generichash_KEYBYTES_MAX,
				"invalid key");
	}
	result_size = VARHDRSZ + crypto_generichash_BYTES;
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_generichash(
		PGSODIUM_UCHARDATA(result),
		crypto_generichash_BYTES,
		PGSODIUM_UCHARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		key,
		keylen);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash_keygen);
Datum
pgsodium_crypto_shorthash_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_shorthash_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_secretbox_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash);
Datum
pgsodium_crypto_shorthash(PG_FUNCTION_ARGS)
{
	bytea* data;
	bytea* result;
	bytea* key;
	int result_size = VARHDRSZ + crypto_shorthash_BYTES;
	data = PG_GETARG_BYTEA_P(0);
	key = PG_GETARG_BYTEA_P(1);
	ERRORIF (VARSIZE_ANY_EXHDR(key) != crypto_shorthash_KEYBYTES, "invalid key");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_shorthash(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_keypair);
Datum
pgsodium_crypto_box_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	size_t public_size = crypto_box_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_box_SECRETKEYBYTES + VARHDRSZ;
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_box_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey));
	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_new_seed);
Datum
pgsodium_crypto_box_new_seed(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_box_SEEDBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seed_keypair);
Datum
pgsodium_crypto_box_seed_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	bytea* seed = PG_GETARG_BYTEA_P(0);
	size_t public_size = crypto_box_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_box_SECRETKEYBYTES + VARHDRSZ;
	ERRORIF(VARSIZE_ANY_EXHDR(seed) != crypto_box_SEEDBYTES, "invalid seed");
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_box_seed_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey),
				PGSODIUM_UCHARDATA(seed));
	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_noncegen);
Datum
pgsodium_crypto_box_noncegen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_box_NONCEBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_box_NONCEBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box);
Datum
pgsodium_crypto_box(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* nonce = PG_GETARG_BYTEA_P(1);
	bytea* publickey = PG_GETARG_BYTEA_P(2);
	bytea* secretkey = PG_GETARG_BYTEA_P(3);
	int success;
	size_t message_size = crypto_box_MACBYTES + VARSIZE_ANY_EXHDR(message);
	bytea* result = _pgsodium_zalloc_bytea(VARHDRSZ + message_size);
	success = crypto_box_easy(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(nonce),
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_open);
Datum
pgsodium_crypto_box_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* nonce = PG_GETARG_BYTEA_P(1);
	bytea* publickey = PG_GETARG_BYTEA_P(2);
	bytea* secretkey = PG_GETARG_BYTEA_P(3);
	size_t message_size;
	bytea* result;

	ERRORIF(VARSIZE_ANY_EXHDR(nonce) != crypto_box_NONCEBYTES, "invalid nonce");
	ERRORIF(VARSIZE_ANY_EXHDR(publickey) != crypto_box_PUBLICKEYBYTES, "invalid public key");
	ERRORIF(VARSIZE_ANY_EXHDR(secretkey) != crypto_box_SECRETKEYBYTES, "invalid secret key");
	ERRORIF(VARSIZE_ANY_EXHDR(message) <= crypto_box_MACBYTES, "invalid message");

	message_size = VARSIZE_ANY_EXHDR(message) - crypto_box_MACBYTES;
	result = _pgsodium_zalloc_bytea(VARHDRSZ + message_size);
	success = crypto_box_open_easy(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(nonce),
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_keypair);
Datum
pgsodium_crypto_sign_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	size_t public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_sign_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey));
	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_new_seed);
Datum
pgsodium_crypto_sign_new_seed(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_sign_SEEDBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_sign_SEEDBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_seed_keypair);
Datum
pgsodium_crypto_sign_seed_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	bytea* seed = PG_GETARG_BYTEA_P(0);
	size_t public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;
	ERRORIF(VARSIZE_ANY_EXHDR(seed) != crypto_sign_SEEDBYTES, "invalid seed");

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_sign_seed_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey),
		PGSODIUM_UCHARDATA(seed));

	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign);
Datum
pgsodium_crypto_sign(PG_FUNCTION_ARGS)
{
	int success;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* secretkey = PG_GETARG_BYTEA_P(1);
	unsigned long long signed_message_len;
	size_t message_size;
	size_t result_size;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(secretkey) != crypto_sign_SECRETKEYBYTES, "invalid secret key");
	message_size = crypto_sign_BYTES + VARSIZE_ANY_EXHDR(message);
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea(result_size);
	success = crypto_sign(
		PGSODIUM_UCHARDATA(result),
		&signed_message_len,
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(secretkey));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_open);
Datum
pgsodium_crypto_sign_open(PG_FUNCTION_ARGS)
{
	int success;
	unsigned long long unsigned_message_len;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* publickey = PG_GETARG_BYTEA_P(1);
	size_t message_size;
	size_t result_size;
	bytea* result;

	ERRORIF(VARSIZE_ANY_EXHDR(publickey) != crypto_sign_PUBLICKEYBYTES, "invalid public key");
	ERRORIF(VARSIZE_ANY_EXHDR(message) <= crypto_sign_BYTES, "invalid message");

	message_size = VARSIZE_ANY_EXHDR(message) - crypto_sign_BYTES;
	result_size = VARHDRSZ + message_size;
	result = _pgsodium_zalloc_bytea(result_size);
	success = crypto_sign_open(
		PGSODIUM_UCHARDATA(result),
		&unsigned_message_len,
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(publickey));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_detached);
Datum
pgsodium_crypto_sign_detached(PG_FUNCTION_ARGS)
{
	int success;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* secretkey = PG_GETARG_BYTEA_P(1);
	size_t sig_size = crypto_sign_BYTES;
	size_t result_size = VARHDRSZ + sig_size;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	ERRORIF(VARSIZE_ANY_EXHDR(secretkey) != crypto_sign_SECRETKEYBYTES, "invalid secret key");
	success = crypto_sign_detached(
		PGSODIUM_UCHARDATA(result),
		NULL,
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(secretkey));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_verify_detached);
Datum
pgsodium_crypto_sign_verify_detached(PG_FUNCTION_ARGS)
{
	int success;
	bytea* sig = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* publickey = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(publickey) != crypto_sign_PUBLICKEYBYTES, "invalid public key");
	success = crypto_sign_verify_detached(
		PGSODIUM_UCHARDATA(sig),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(publickey));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_init);
Datum pgsodium_crypto_sign_init(PG_FUNCTION_ARGS)
{
	bytea* result = _pgsodium_zalloc_bytea(
		VARHDRSZ +sizeof(crypto_sign_state));
	SET_VARSIZE(result, sizeof(crypto_sign_state));
	crypto_sign_init((crypto_sign_state*) VARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_update);
Datum pgsodium_crypto_sign_update(PG_FUNCTION_ARGS)
{
	bytea* state = PG_GETARG_BYTEA_P(0);	   // input state
	bytea* msg_part = PG_GETARG_BYTEA_P(1);
	bytea* result = DatumGetByteaPCopy(state); // output state

	crypto_sign_update(
		(crypto_sign_state*) VARDATA(result),
		PGSODIUM_UCHARDATA(msg_part),
		VARSIZE_ANY_EXHDR(msg_part));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_final_create);
Datum pgsodium_crypto_sign_final_create(PG_FUNCTION_ARGS)
{
	int success;
	bytea* state = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	size_t sig_size = crypto_sign_BYTES;
	size_t result_size = VARHDRSZ + sig_size;
	bytea* result = _pgsodium_zalloc_bytea(result_size);

	// Make a copy of state so that we do not stomp over the
	// user-facing datum.
	bytea* local_state = DatumGetByteaPCopy(state);
	success = crypto_sign_final_create(
		(crypto_sign_state*) VARDATA(local_state),
		PGSODIUM_UCHARDATA(result),
		NULL,
		PGSODIUM_UCHARDATA(key));
	pfree(local_state);

	ERRORIF(success != 0, "unable to complete signature");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_final_verify);
Datum pgsodium_crypto_sign_final_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* state = PG_GETARG_BYTEA_P(0);
	bytea* sig = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);

	// Make a copy of state so that we do not stomp over the
	// user-facing datum.
	bytea* local_state = DatumGetByteaPCopy(state);
	success = crypto_sign_final_verify(
		(crypto_sign_state*) VARDATA(local_state),
		PGSODIUM_UCHARDATA(sig),
		PGSODIUM_UCHARDATA(key));
	pfree(local_state);
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_saltgen);
Datum
pgsodium_crypto_pwhash_saltgen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_pwhash_SALTBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_pwhash_SALTBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash);
Datum
pgsodium_crypto_pwhash(PG_FUNCTION_ARGS)
{
	bytea* data;
	bytea* result;
	bytea* salt;
	int result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	int success;
	data = PG_GETARG_BYTEA_P(0);
	salt = PG_GETARG_BYTEA_P(1);
	ERRORIF(VARSIZE_ANY_EXHDR(salt) != crypto_pwhash_SALTBYTES, "invalid salt");
	result = _pgsodium_zalloc_bytea(result_size);
	success = crypto_pwhash(
		PGSODIUM_UCHARDATA(result),
		crypto_box_SEEDBYTES,
		VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		PGSODIUM_UCHARDATA(salt),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT);
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str);
Datum
pgsodium_crypto_pwhash_str(PG_FUNCTION_ARGS)
{
	int success;
	bytea* password = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(crypto_pwhash_STRBYTES);
	success = crypto_pwhash_str(
		VARDATA(result),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE);
	ERRORIF(success != 0, "out of memory in pwhash_str");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str_verify);
Datum
pgsodium_crypto_pwhash_str_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hashed_password = PG_GETARG_BYTEA_P(0);
	bytea* password = PG_GETARG_BYTEA_P(1);
	success = crypto_pwhash_str_verify(
		VARDATA(hashed_password),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal);
Datum
pgsodium_crypto_box_seal(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* public_key = PG_GETARG_BYTEA_P(1);
	size_t result_size;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(public_key) != crypto_box_PUBLICKEYBYTES, "invalid public key");
	result_size = crypto_box_SEALBYTES + VARSIZE(message);
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_box_seal(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(public_key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal_open);
Datum
pgsodium_crypto_box_seal_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea* ciphertext = PG_GETARG_BYTEA_P(0);
	bytea* public_key = PG_GETARG_BYTEA_P(1);
	bytea* secret_key = PG_GETARG_BYTEA_P(2);
	size_t result_size;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(public_key) != crypto_box_PUBLICKEYBYTES, "invalid public key");
	ERRORIF(VARSIZE_ANY_EXHDR(secret_key) != crypto_box_SECRETKEYBYTES, "invalid secret key");
	ERRORIF(VARSIZE_ANY_EXHDR(ciphertext) <= crypto_box_SEALBYTES, "invalid message");

	result_size = VARSIZE(ciphertext) - crypto_box_SEALBYTES;
	result = _pgsodium_zalloc_bytea(result_size);
	success = crypto_box_seal_open(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(ciphertext),
		VARSIZE_ANY_EXHDR(ciphertext),
		PGSODIUM_UCHARDATA(public_key),
		PGSODIUM_UCHARDATA(secret_key));
	ERRORIF(success != 0, "invalid message");
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kdf_keygen);
Datum
pgsodium_crypto_kdf_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_kdf_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_kdf_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kdf_derive_from_key);
Datum
pgsodium_crypto_kdf_derive_from_key(PG_FUNCTION_ARGS)
{
	size_t subkey_size = PG_GETARG_UINT32(0);
	size_t result_size = VARHDRSZ + subkey_size;
	unsigned long long subkey_id = PG_GETARG_INT64(1);
	bytea* context = PG_GETARG_BYTEA_P(2);
	bytea* primary_key = PG_GETARG_BYTEA_P(3);
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(primary_key) != crypto_kdf_KEYBYTES,
			"invalid derivation key");
	ERRORIF(subkey_size < crypto_kdf_BYTES_MIN || subkey_size > crypto_kdf_BYTES_MAX,
			"crypto_kdf_derive_from_key: invalid key size requested");
	ERRORIF(VARSIZE_ANY_EXHDR(context) != 8,
			"crypto_kdf_derive_from_key: context must be 8 bytes");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_kdf_derive_from_key(
		PGSODIUM_UCHARDATA(result),
		subkey_size,
		subkey_id,
		(const char*)VARDATA(context),
		PGSODIUM_UCHARDATA(primary_key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_keypair);
Datum
pgsodium_crypto_kx_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	size_t public_size = crypto_kx_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_kx_SECRETKEYBYTES + VARHDRSZ;
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_kx_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey));
	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_seed_keypair);
Datum
pgsodium_crypto_kx_seed_keypair(PG_FUNCTION_ARGS)
{
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* publickey;
	bytea* secretkey;
	bytea* seed = PG_GETARG_BYTEA_P(0);
	size_t public_size = crypto_kx_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_kx_SECRETKEYBYTES + VARHDRSZ;
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	ERRORIF(VARSIZE_ANY_EXHDR(seed) != crypto_kx_SEEDBYTES, "invalid seed");
	publickey = _pgsodium_zalloc_bytea(public_size);
	secretkey = _pgsodium_zalloc_bytea(secret_size);
	crypto_kx_seed_keypair(
		PGSODIUM_UCHARDATA(publickey),
		PGSODIUM_UCHARDATA(secretkey),
		PGSODIUM_UCHARDATA(seed));
	values[0] = PointerGetDatum(publickey);
	values[1] = PointerGetDatum(secretkey);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_new_seed);
Datum
pgsodium_crypto_kx_new_seed(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_kx_SEEDBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	randombytes_buf(VARDATA(result), crypto_kx_SEEDBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_client_session_keys);
Datum
pgsodium_crypto_kx_client_session_keys(PG_FUNCTION_ARGS)
{
	int success;
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* rx;
	bytea* tx;
	bytea* client_pk = PG_GETARG_BYTEA_P(0);
	bytea* client_sk = PG_GETARG_BYTEA_P(1);
	bytea* server_pk = PG_GETARG_BYTEA_P(2);
	size_t rx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
	size_t tx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	ERRORIF(VARSIZE_ANY_EXHDR(client_pk) != crypto_kx_PUBLICKEYBYTES, "bad client public key");
	ERRORIF(VARSIZE_ANY_EXHDR(client_sk) != crypto_kx_SECRETKEYBYTES, "bad client secret key");
	ERRORIF(VARSIZE_ANY_EXHDR(server_pk) != crypto_kx_PUBLICKEYBYTES, "bad server public key");
	rx = _pgsodium_zalloc_bytea(rx_size);
	tx = _pgsodium_zalloc_bytea(tx_size);
	success = crypto_kx_client_session_keys(
		PGSODIUM_UCHARDATA(rx),
		PGSODIUM_UCHARDATA(tx),
		PGSODIUM_UCHARDATA(client_pk),
		PGSODIUM_UCHARDATA(client_sk),
		PGSODIUM_UCHARDATA(server_pk));
	ERRORIF(success != 0, "invalid message");
	values[0] = PointerGetDatum(rx);
	values[1] = PointerGetDatum(tx);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_kx_server_session_keys);
Datum
pgsodium_crypto_kx_server_session_keys(PG_FUNCTION_ARGS)
{
	int success;
	TupleDesc tupdesc;
	Datum values[2];
	bool nulls[2] = {false, false};
	HeapTuple tuple;
	Datum result;
	bytea* rx;
	bytea* tx;
	bytea* server_pk = PG_GETARG_BYTEA_P(0);
	bytea* server_sk = PG_GETARG_BYTEA_P(1);
	bytea* client_pk = PG_GETARG_BYTEA_P(2);
	size_t rx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
	size_t tx_size = crypto_kx_SESSIONKEYBYTES + VARHDRSZ;
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	ERRORIF(VARSIZE_ANY_EXHDR(server_pk) != crypto_kx_PUBLICKEYBYTES, "bad server public key");
	ERRORIF(VARSIZE_ANY_EXHDR(server_sk) != crypto_kx_SECRETKEYBYTES, "bad server secret key");
	ERRORIF(VARSIZE_ANY_EXHDR(client_pk) != crypto_kx_PUBLICKEYBYTES, "bad client public key");
	rx = _pgsodium_zalloc_bytea(rx_size);
	tx = _pgsodium_zalloc_bytea(tx_size);
	success = crypto_kx_server_session_keys(
		PGSODIUM_UCHARDATA(rx),
		PGSODIUM_UCHARDATA(tx),
		PGSODIUM_UCHARDATA(server_pk),
		PGSODIUM_UCHARDATA(server_sk),
		PGSODIUM_UCHARDATA(client_pk));
	ERRORIF(success != 0, "invalid message");
	values[0] = PointerGetDatum(rx);
	values[1] = PointerGetDatum(tx);
	tuple = heap_form_tuple(tupdesc, values, nulls);
	result = HeapTupleGetDatum(tuple);
	return result;
}

/* Advanced */

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512_keygen);
Datum
pgsodium_crypto_auth_hmacsha512_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha512_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha512_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512);
Datum
pgsodium_crypto_auth_hmacsha512(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha512_BYTES;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha512_KEYBYTES, "invalid key");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha512(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha512_verify);
Datum
pgsodium_crypto_auth_hmacsha512_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hash = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(hash) != crypto_auth_hmacsha512_BYTES, "invalid hash");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha512_KEYBYTES, "invalid key");
	success = crypto_auth_hmacsha512_verify(
		PGSODIUM_UCHARDATA(hash),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256_keygen);
Datum
pgsodium_crypto_auth_hmacsha256_keygen(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha256_KEYBYTES;
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha256_keygen(PGSODIUM_UCHARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256);
Datum
pgsodium_crypto_auth_hmacsha256(PG_FUNCTION_ARGS)
{
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* key = PG_GETARG_BYTEA_P(1);
	size_t result_size = VARHDRSZ + crypto_auth_hmacsha256_BYTES;
	bytea* result;
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha256_KEYBYTES, "invalid key");
	result = _pgsodium_zalloc_bytea(result_size);
	crypto_auth_hmacsha256(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_hmacsha256_verify);
Datum
pgsodium_crypto_auth_hmacsha256_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea* hash = PG_GETARG_BYTEA_P(0);
	bytea* message = PG_GETARG_BYTEA_P(1);
	bytea* key = PG_GETARG_BYTEA_P(2);
	ERRORIF(VARSIZE_ANY_EXHDR(hash) != crypto_auth_hmacsha256_BYTES, "invalid hash");
	ERRORIF(VARSIZE_ANY_EXHDR(key) != crypto_auth_hmacsha256_KEYBYTES, "invalid key");
	success = crypto_auth_hmacsha256_verify(
		PGSODIUM_UCHARDATA(hash),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		PGSODIUM_UCHARDATA(key));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_hash_sha256);
Datum
pgsodium_crypto_hash_sha256(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_hash_sha256_BYTES;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_hash_sha256(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_hash_sha512);
Datum
pgsodium_crypto_hash_sha512(PG_FUNCTION_ARGS)
{
	size_t result_size = VARHDRSZ + crypto_hash_sha512_BYTES;
	bytea* message = PG_GETARG_BYTEA_P(0);
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	crypto_hash_sha512(
		PGSODIUM_UCHARDATA(result),
		PGSODIUM_UCHARDATA(message),
		VARSIZE_ANY_EXHDR(message));
	PG_RETURN_BYTEA_P(result);
}

/* Server key management */

PG_FUNCTION_INFO_V1(pgsodium_derive);
Datum
pgsodium_derive(PG_FUNCTION_ARGS)
{
	unsigned long long subkey_id = PG_GETARG_INT64(0);
	size_t subkey_size = PG_GETARG_UINT32(1);
	size_t result_size = VARHDRSZ + subkey_size;
	bytea* context = PG_GETARG_BYTEA_P(2);
	bytea* result = _pgsodium_zalloc_bytea(result_size);
	ERRORIF(pgsodium_secret_key == NULL,
			"pgsodium_derive: no server secret key defined.");
	ERRORIF(subkey_size < crypto_kdf_BYTES_MIN || subkey_size > crypto_kdf_BYTES_MAX,
			"crypto_kdf_derive_from_key: invalid key size requested");
	ERRORIF(VARSIZE_ANY_EXHDR(context) != 8,
			"crypto_kdf_derive_from_key: context must be 8 bytes");
	crypto_kdf_derive_from_key(
		PGSODIUM_UCHARDATA(result),
		subkey_size,
		subkey_id,
		(const char*)VARDATA(context),
		PGSODIUM_UCHARDATA(pgsodium_secret_key));
	PG_RETURN_BYTEA_P(result);
}

const char* secret_noshow_hook (void) {
	return "****************************************************************";
}

void _PG_init(void)
{
	FILE* fp;
	char* secret_buf;
	size_t secret_len = 0;
	size_t char_read;
	char* path;

	char sharepath[MAXPGPATH];

	if (sodium_init() == -1)
	{
		elog(ERROR, "_PG_init: sodium_init() failed cannot initialize pgsodium");
		return;
	}

	if (process_shared_preload_libraries_in_progress)
	{
		get_share_path(my_exec_path, sharepath);
		path = (char*) palloc(MAXPGPATH);
		snprintf(
			path,
			MAXPGPATH,
			"%s/extension/%s",
			sharepath,
			PG_GETKEY_EXEC);

		if (access(path, F_OK) == -1)
			return;

		if ((fp = popen(path, "r")) == NULL)
		{
			fprintf(stderr,
					"%s: could not launch shell command from\n",
					path);
			proc_exit(1);
		}

		char_read = getline(&secret_buf, &secret_len, fp);
		if (secret_buf[char_read-1] == '\n')
			secret_buf[char_read-1] = '\0';

		secret_len = strlen(secret_buf);

		if (secret_len != 64)
		{
			fprintf(stderr, "invalid secret key\n");
			proc_exit(1);
		}

		if (pclose(fp) != 0)
		{
			fprintf(stderr, "%s: could not close shell command\n",
					PG_GETKEY_EXEC);
			proc_exit(1);
		}
		pgsodium_secret_key = palloc(crypto_sign_SECRETKEYBYTES + VARHDRSZ);
		hex_decode(secret_buf, secret_len, VARDATA(pgsodium_secret_key));
		sodium_mlock(pgsodium_secret_key, crypto_sign_SECRETKEYBYTES + VARHDRSZ);
		memset(secret_buf, 0, secret_len);
		free(secret_buf);
	}
}
