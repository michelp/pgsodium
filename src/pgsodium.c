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
Datum pgsodium_crypto_secretbox_keygen(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_secretbox_KEYBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_secretbox_KEYBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(buff);
	memmove(ret->vl_dat, buff, crypto_secretbox_KEYBYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox_noncegen);
Datum pgsodium_crypto_secretbox_noncegen(PG_FUNCTION_ARGS)
{
	unsigned char buff[crypto_secretbox_KEYBYTES];
	bytea *ret = (bytea *) palloc(VARHDRSZ + crypto_secretbox_NONCEBYTES);
	SET_VARSIZE(ret, VARHDRSZ + crypto_secretbox_NONCEBYTES);
	randombytes_buf(buff, crypto_secretbox_NONCEBYTES);
	memmove(ret->vl_dat, buff, crypto_secretbox_NONCEBYTES);
	PG_RETURN_BYTEA_P(ret);
}

PG_FUNCTION_INFO_V1(pgsodium_crypto_secretbox);
Datum pgsodium_crypto_secretbox(PG_FUNCTION_ARGS)
{
    text *message = PG_GETARG_TEXT_P(0);
	bytea *key = PG_GETARG_BYTEA_P(1);
	bytea *nonce = PG_GETARG_BYTEA_P(2);

	size_t message_size = crypto_secretbox_MACBYTES + VARSIZE(message);
	unsigned char buff[message_size];
	bytea *ret = (bytea *) palloc(VARHDRSZ + message_size);
	SET_VARSIZE(ret, VARHDRSZ + message_size);
	crypto_secretbox_easy(buff, (const unsigned char*)VARDATA(message), VARSIZE(message),
						  (const unsigned char*)VARDATA(nonce), (const unsigned char*)VARDATA(key));
	memmove(ret->vl_dat, buff, message_size);
	PG_RETURN_BYTEA_P(ret);
}

void _PG_init(void) {
	if (sodium_init() == -1) {
		elog(ERROR, "_PG_init: sodium_init() failed cannot initialize pgsodium");
		return;
	}
}
