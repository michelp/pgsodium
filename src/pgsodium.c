#include "pgsodium.h"
PG_MODULE_MAGIC;

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
	bytea *ret = (bytea *) palloc(VARHDRSZ + size);
	SET_VARSIZE(ret, VARHDRSZ + size);
	randombytes_buf(VARDATA(ret), size);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_keygen);
Datum
pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_secretbox_KEYBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_secretbox_KEYBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(buff);
	memcpy((void*)VARDATA(ret), buff, crypto_secretbox_KEYBYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_noncegen);
Datum
pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_secretbox_NONCEBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_secretbox_NONCEBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_secretbox_NONCEBYTES);
	randombytes_buf(buff, crypto_secretbox_NONCEBYTES);
	memcpy((void*)VARDATA(ret), buff, crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox);
Datum
pgsodium_crypto_secretbox(PG_FUNCTION_ARGS)
{
	text *message = PG_GETARG_TEXT_P(0);
	bytea *key = PG_GETARG_BYTEA_P(1);
	bytea *nonce = PG_GETARG_BYTEA_P(2);
	size_t message_size = crypto_secretbox_MACBYTES + VARSIZE_ANY_EXHDR(message);
	bytea *ret = (bytea *) palloc(VARHDRSZ + message_size);
	unsigned char *buff = (unsigned char*) palloc(message_size);
	SET_VARSIZE(ret, VARHDRSZ + message_size);
	crypto_secretbox_easy(
		buff,
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(nonce),
		(const unsigned char*)VARDATA(key));
	memcpy((void*)VARDATA(ret), buff, message_size);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_open);
Datum
pgsodium_crypto_secretbox_open(PG_FUNCTION_ARGS)
{
	int success;
	bytea *message = PG_GETARG_BYTEA_P(0);
	bytea *key = PG_GETARG_BYTEA_P(1);
	bytea *nonce = PG_GETARG_BYTEA_P(2);
	size_t message_size = VARSIZE_ANY_EXHDR(message) - crypto_secretbox_MACBYTES;
	text *ret = (text *) palloc(VARHDRSZ + message_size);
	unsigned char *buff = (unsigned char*) palloc(message_size);
	SET_VARSIZE(ret, VARHDRSZ + message_size);
	success = crypto_secretbox_open_easy(
		buff,
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(nonce),
		(const unsigned char*)VARDATA(key));
	if (success != 0) {
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	}
	memcpy((void*)VARDATA(ret), buff, message_size);
	PG_RETURN_TEXT_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth);
Datum
pgsodium_crypto_auth(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_auth_BYTES];
	text *message = PG_GETARG_TEXT_P(0);
	bytea *key = PG_GETARG_BYTEA_P(1);
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_auth_BYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_auth_BYTES);
	crypto_auth(
		buff,
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(key));
	memcpy((void*)VARDATA(ret), buff, crypto_auth_BYTES);
	PG_RETURN_BYTEA_P(ret);
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
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(key));
	if (success != 0) {
		PG_RETURN_BOOL(0);
	}
	PG_RETURN_BOOL(1);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_auth_keygen);
Datum
pgsodium_crypto_auth_keygen(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_auth_KEYBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_auth_KEYBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_auth_KEYBYTES);
	crypto_secretbox_keygen(buff);
	memcpy((void*)VARDATA(ret), buff, crypto_auth_KEYBYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_generichash);
Datum
pgsodium_crypto_generichash(PG_FUNCTION_ARGS)
{
	unsigned char hash[crypto_generichash_BYTES];
	text *data;
	bytea *ret;
	bytea *keyarg;
	unsigned char *key = NULL;
	size_t keylen = 0;

	data = PG_GETARG_TEXT_P(0);
	if (!PG_ARGISNULL(1)) {
		keyarg = PG_GETARG_BYTEA_P(1);
		key = (unsigned char*)VARDATA(keyarg);
		keylen = VARSIZE_ANY_EXHDR(keyarg);
	}

	ret = (bytea *) palloc(VARHDRSZ + crypto_generichash_BYTES);
	crypto_generichash(
		hash,
		sizeof hash,
		(unsigned char*)VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		key,
		keylen);
	memcpy((void*)VARDATA(ret), hash, crypto_generichash_BYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_generichash_BYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_shorthash);
Datum
pgsodium_crypto_shorthash(PG_FUNCTION_ARGS)
{
	unsigned char hash[crypto_shorthash_BYTES];
	text *data;
	bytea *ret;
	bytea *key;

	data = PG_GETARG_TEXT_P(0);
	key = PG_GETARG_BYTEA_P(1);
	if (VARSIZE_ANY_EXHDR(key) != crypto_shorthash_KEYBYTES)
		PG_RETURN_NULL();

	ret = (bytea *) palloc(VARHDRSZ + crypto_shorthash_BYTES);
	crypto_shorthash(
		hash,
		(unsigned char*)VARDATA(data),
		VARSIZE_ANY_EXHDR(data),
		(unsigned char*)VARDATA(key));
	memcpy((void*)VARDATA(ret), hash, crypto_shorthash_BYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_shorthash_BYTES);
	PG_RETURN_BYTEA_P(ret);
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
	unsigned char pkey[crypto_box_PUBLICKEYBYTES];
	unsigned char skey[crypto_box_SECRETKEYBYTES];
	bytea *publickey;
	bytea *secretkey;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));
	
	publickey = (bytea *) palloc(crypto_box_PUBLICKEYBYTES + VARHDRSZ);
	secretkey = (bytea *) palloc(crypto_box_SECRETKEYBYTES + VARHDRSZ);
	SET_VARSIZE(publickey, VARHDRSZ + crypto_box_PUBLICKEYBYTES);
	SET_VARSIZE(secretkey, VARHDRSZ + crypto_box_SECRETKEYBYTES);
	
	crypto_box_keypair(pkey, skey);

	memcpy((void*)VARDATA(publickey), pkey, crypto_box_PUBLICKEYBYTES);
	memcpy((void*)VARDATA(secretkey), skey, crypto_box_PUBLICKEYBYTES);

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
	unsigned char buff[crypto_box_NONCEBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_box_NONCEBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_box_NONCEBYTES);
	randombytes_buf(buff, crypto_box_NONCEBYTES);
	memcpy((void*)VARDATA(ret), buff, crypto_box_NONCEBYTES);
	PG_RETURN_BYTEA_P(ret);
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
	bytea *ret = (bytea *) palloc(VARHDRSZ + message_size);
	unsigned char *buff = (unsigned char*) palloc(message_size);
	SET_VARSIZE(ret, VARHDRSZ + message_size);
	success = crypto_box_easy(
		buff,
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(nonce),
		(const unsigned char*)VARDATA(publickey),
		(const unsigned char*)VARDATA(secretkey)
		);
	if (success != 0) {
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	}
	
	memcpy((void*)VARDATA(ret), buff, message_size);
	PG_RETURN_BYTEA_P(ret);
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
	text *ret = (text *) palloc(VARHDRSZ + message_size);
	unsigned char *buff = (unsigned char*) palloc(message_size);
	SET_VARSIZE(ret, VARHDRSZ + message_size);
	success = crypto_box_open_easy(
		buff,
		(const unsigned char*)VARDATA(message),
		VARSIZE_ANY_EXHDR(message),
		(const unsigned char*)VARDATA(nonce),
		(const unsigned char*)VARDATA(publickey),
		(const unsigned char*)VARDATA(secretkey));
	if (success != 0) {
		ereport(
			ERROR,
			(errcode(ERRCODE_DATA_EXCEPTION),
			 errmsg("invalid message")));
	}
	memcpy((void*)VARDATA(ret), buff, message_size);
	PG_RETURN_TEXT_P(ret);
}

void _PG_init(void)
{
	if (sodium_init() == -1)
	{
		elog(ERROR, "_PG_init: sodium_init() failed cannot initialize pgsodium");
		return;
	}
}

