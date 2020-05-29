#include "pgsodium.h"
PG_MODULE_MAGIC;

static void
context_cb_zero_buff(void* a) {
  pgsodium_cb_data *data = (pgsodium_cb_data *) a;
  sodium_memzero(data->ptr, data->size);
}

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
	unsigned long long result_size = VARHDRSZ + size;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	randombytes_buf(VARDATA(result), size);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_keygen);
Datum
pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS)
{
	unsigned long long result_size = VARHDRSZ + crypto_secretbox_KEYBYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	crypto_secretbox_keygen((unsigned char*)VARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_noncegen);
Datum
pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS)
{
	int result_size = VARHDRSZ + crypto_secretbox_NONCEBYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	randombytes_buf(VARDATA(result), crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox);
Datum
pgsodium_crypto_secretbox(PG_FUNCTION_ARGS)
{
	text *message = PG_GETARG_TEXT_P(0);
	bytea *nonce = PG_GETARG_BYTEA_P(1);
	bytea *key = PG_GETARG_BYTEA_P(2);
	size_t message_size = crypto_secretbox_MACBYTES + VARSIZE_ANY_EXHDR(message);
	unsigned long long result_size = VARHDRSZ + message_size;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	crypto_secretbox_easy(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(nonce),
		(unsigned char*)VARDATA(key));

	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_open);
Datum
pgsodium_crypto_secretbox_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea *message = PG_GETARG_BYTEA_P(0);
	bytea *nonce = PG_GETARG_BYTEA_P(1);
	bytea *key = PG_GETARG_BYTEA_P(2);
	size_t message_size = VARSIZE_ANY_EXHDR(message) - crypto_secretbox_MACBYTES;
	unsigned long long result_size = VARHDRSZ + message_size;
	text *result = (text *) palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	success = crypto_secretbox_open_easy(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(nonce),
		(unsigned char*)VARDATA(key));

	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));

	PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth);
Datum
pgsodium_crypto_auth(PG_FUNCTION_ARGS)
{
	text *message = PG_GETARG_TEXT_P(0);
	bytea *key = PG_GETARG_BYTEA_P(1);
	int result_size = VARHDRSZ + crypto_auth_BYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	crypto_auth(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_verify);
Datum
pgsodium_crypto_auth_verify(PG_FUNCTION_ARGS)
{
	int success;
	bytea *mac = PG_GETARG_BYTEA_P(0);
	text *message = PG_GETARG_BYTEA_P(1);
	bytea *key = PG_GETARG_BYTEA_P(2);

	success = crypto_auth_verify(
		(unsigned char*)VARDATA(mac),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(key));
	PG_RETURN_BOOL(success == 0);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_keygen);
Datum
pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS)
{
	unsigned long long result_size = VARHDRSZ + crypto_auth_KEYBYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	crypto_secretbox_keygen((unsigned char*)VARDATA(result));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash);
Datum
pgsodium_crypto_generichash(PG_FUNCTION_ARGS)
{
	text *data;
	bytea *result;
	bytea *keyarg;
	unsigned char *key = NULL;
	size_t keylen = 0;
	unsigned long long result_size;

	data = PG_GETARG_TEXT_P(0);
	if (!PG_ARGISNULL(1))
	{
		keyarg = PG_GETARG_BYTEA_P(1);
		key = (unsigned char*)VARDATA(keyarg);
		keylen = VARSIZE_ANY_EXHDR(keyarg);
	}

	result_size = VARHDRSZ + crypto_generichash_BYTES;
	result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	crypto_generichash(
		(unsigned char*)VARDATA(result),
		crypto_generichash_BYTES,
		(unsigned char*)VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		key,
		keylen);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash);
Datum
pgsodium_crypto_shorthash(PG_FUNCTION_ARGS)
{
	text *data;
	bytea *result;
	bytea *key;
	int result_size = VARHDRSZ + crypto_shorthash_BYTES;

	data = PG_GETARG_TEXT_P(0);
	key = PG_GETARG_BYTEA_P(1);
	if (VARSIZE_ANY_EXHDR(key) != crypto_shorthash_KEYBYTES)
		PG_RETURN_NULL();

	result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	crypto_shorthash(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		(unsigned char*)VARDATA(key));
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
	bytea *publickey;
	bytea *secretkey;
	size_t public_size = crypto_box_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_box_SECRETKEYBYTES + VARHDRSZ;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	publickey = (bytea*)palloc(public_size);
        ZERO_BUFF_CB(publickey, public_size);
	secretkey = (bytea*)palloc(secret_size);
        ZERO_BUFF_CB(secretkey, secret_size);
	SET_VARSIZE(publickey, public_size);
	SET_VARSIZE(secretkey, secret_size);

	crypto_box_keypair(
		(unsigned char*)VARDATA(publickey),
		(unsigned char*)VARDATA(secretkey)
		);

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
	unsigned long long result_size = VARHDRSZ + crypto_box_NONCEBYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	randombytes_buf(VARDATA(result), crypto_box_NONCEBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box);
Datum
pgsodium_crypto_box(PG_FUNCTION_ARGS)
{
	text *message = PG_GETARG_TEXT_P(0);
	bytea *nonce = PG_GETARG_BYTEA_P(1);
	bytea *publickey = PG_GETARG_BYTEA_P(2);
	bytea *secretkey = PG_GETARG_BYTEA_P(3);
	int success;

	size_t message_size = crypto_box_MACBYTES + VARSIZE_ANY_EXHDR(message);
	bytea *result = (bytea*)palloc(VARHDRSZ + message_size);
        ZERO_BUFF_CB(result, VARHDRSZ + message_size);
	SET_VARSIZE(result, VARHDRSZ + message_size);
	success = crypto_box_easy(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(nonce),
		(unsigned char*)VARDATA(publickey),
		(unsigned char*)VARDATA(secretkey)
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));

	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_open);
Datum
pgsodium_crypto_box_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea *message = PG_GETARG_BYTEA_P(0);
	bytea *nonce = PG_GETARG_BYTEA_P(1);
	bytea *publickey = PG_GETARG_BYTEA_P(2);
	bytea *secretkey = PG_GETARG_BYTEA_P(3);

	size_t message_size = VARSIZE_ANY_EXHDR(message) - crypto_box_MACBYTES;
	text *result = (text *) palloc(VARHDRSZ + message_size);
        ZERO_BUFF_CB(result, VARHDRSZ + message_size);
	SET_VARSIZE(result, VARHDRSZ + message_size);
	success = crypto_box_open_easy(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(nonce),
		(unsigned char*)VARDATA(publickey),
		(unsigned char*)VARDATA(secretkey));
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	PG_RETURN_TEXT_P(result);
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
	bytea *publickey;
	bytea *secretkey;
	size_t public_size = crypto_sign_PUBLICKEYBYTES + VARHDRSZ;
	size_t secret_size = crypto_sign_SECRETKEYBYTES + VARHDRSZ;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	publickey = (bytea*)palloc(public_size);
        ZERO_BUFF_CB(publickey, public_size);
	secretkey = (bytea*)palloc(secret_size);
        ZERO_BUFF_CB(secretkey, secret_size);
	SET_VARSIZE(publickey, public_size);
	SET_VARSIZE(secretkey, secret_size);

	crypto_sign_keypair(
		(unsigned char*)VARDATA(publickey),
		(unsigned char*)VARDATA(secretkey)
		);

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
	text *message = PG_GETARG_TEXT_P(0);
	bytea *secretkey = PG_GETARG_BYTEA_P(1);
	unsigned long long signed_message_len;
	size_t message_size = crypto_sign_BYTES + VARSIZE_ANY_EXHDR(message);
	unsigned long long result_size = VARHDRSZ + message_size;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	success = crypto_sign(
		(unsigned char*)VARDATA(result),
		&signed_message_len,
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(secretkey)
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_open);
Datum
pgsodium_crypto_sign_open(PG_FUNCTION_ARGS)
{
	int success;
	unsigned long long unsigned_message_len;
	bytea *message = PG_GETARG_BYTEA_P(0);
	bytea *publickey = PG_GETARG_BYTEA_P(1);
	size_t message_size = VARSIZE_ANY_EXHDR(message) - crypto_sign_BYTES;
	unsigned long long result_size = VARHDRSZ + message_size;
	text *result = (text *) palloc(result_size);
        ZERO_BUFF_CB(result, result_size);

	SET_VARSIZE(result, result_size);
	success = crypto_sign_open(
		(unsigned char*)VARDATA(result),
		&unsigned_message_len,
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(publickey)
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_detached);
Datum
pgsodium_crypto_sign_detached(PG_FUNCTION_ARGS)
{
	int success;
	bytea *message = PG_GETARG_BYTEA_P(0);
	bytea *secretkey = PG_GETARG_BYTEA_P(1);
	size_t sig_size = crypto_sign_BYTES;
	unsigned long long result_size = VARHDRSZ + sig_size;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	success = crypto_sign_detached(
		(unsigned char*)VARDATA(result),
		NULL,
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(secretkey)
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_sign_verify_detached);
Datum
pgsodium_crypto_sign_verify_detached(PG_FUNCTION_ARGS)
{
	int success;
	bytea *sig = PG_GETARG_BYTEA_P(0);
	bytea *message = PG_GETARG_BYTEA_P(1);
	bytea *publickey = PG_GETARG_BYTEA_P(2);

	success = crypto_sign_verify_detached(
	        (unsigned char*)VARDATA(sig),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(publickey)
		);
	if (success == 0) 
		PG_RETURN_BOOL(true);
	else
		PG_RETURN_BOOL(false);
}


PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_saltgen);
Datum
pgsodium_crypto_pwhash_saltgen(PG_FUNCTION_ARGS)
{
	unsigned long long result_size = VARHDRSZ + crypto_pwhash_SALTBYTES;
	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);
	randombytes_buf(VARDATA(result), crypto_pwhash_SALTBYTES);
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash);
Datum
pgsodium_crypto_pwhash(PG_FUNCTION_ARGS)
{
	text *data;
	bytea *result;
	bytea *salt;
	int result_size = VARHDRSZ + crypto_box_SEEDBYTES;
	int success;

	data = PG_GETARG_TEXT_P(0);
	salt = PG_GETARG_BYTEA_P(1);
	if (VARSIZE_ANY_EXHDR(salt) != crypto_pwhash_SALTBYTES)
		PG_RETURN_NULL();

	result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	success = crypto_pwhash(
		(unsigned char*)VARDATA(result),
		crypto_box_SEEDBYTES,
		VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		(unsigned char*)VARDATA(salt),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str);
Datum
pgsodium_crypto_pwhash_str(PG_FUNCTION_ARGS)
{
	int success;
	text *password = PG_GETARG_TEXT_P(0);
	text *result = (text *)palloc(crypto_pwhash_STRBYTES);
        ZERO_BUFF_CB(result, crypto_pwhash_STRBYTES);
	SET_VARSIZE(result, crypto_pwhash_STRBYTES);

	success = crypto_pwhash_str(
		VARDATA(result),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password),
		crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE);

	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("out of memory in pwhash_str")));
	PG_RETURN_TEXT_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_pwhash_str_verify);
Datum
pgsodium_crypto_pwhash_str_verify(PG_FUNCTION_ARGS)
{
	int success;
	text *hashed_password = PG_GETARG_TEXT_P(0);
	text *password = PG_GETARG_TEXT_P(1);
	success = crypto_pwhash_str_verify(
		VARDATA(hashed_password),
		VARDATA(password),
		VARSIZE_ANY_EXHDR(password)
		);
	PG_RETURN_BOOL(success == 0);
}


PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal);
Datum
pgsodium_crypto_box_seal(PG_FUNCTION_ARGS)
{
	text *message = PG_GETARG_TEXT_P(0);
    bytea *public_key = PG_GETARG_BYTEA_P(1);
    unsigned long long result_size = crypto_box_SEALBYTES + VARSIZE(message);

	bytea *result = (bytea*)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

    crypto_box_seal(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(unsigned char*)VARDATA(public_key));
	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_box_seal_open);
Datum
pgsodium_crypto_box_seal_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea *ciphertext = PG_GETARG_BYTEA_P(0);
	bytea *public_key = PG_GETARG_BYTEA_P(1);
	bytea *secret_key = PG_GETARG_BYTEA_P(2);

	unsigned long long result_size = VARSIZE(ciphertext) - crypto_box_SEALBYTES;
	text *result = (text *)palloc(result_size);
        ZERO_BUFF_CB(result, result_size);
	SET_VARSIZE(result, result_size);

	success = crypto_box_seal_open(
		(unsigned char*)VARDATA(result),
		(unsigned char*)VARDATA(ciphertext),
		VARSIZE_ANY_EXHDR(ciphertext),
		(unsigned char*)VARDATA(public_key),
		(unsigned char*)VARDATA(secret_key)
		);
	if (success != 0)
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("crypto_box_seal_open: invalid message")));
	PG_RETURN_TEXT_P(result);
}

void _PG_init(void)
{
	if (sodium_init() == -1)
	{
		elog(ERROR, "_PG_init: sodium_init() failed cannot initialize pgsodium");
		return;
	}
}
