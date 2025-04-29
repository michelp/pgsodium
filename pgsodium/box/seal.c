#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_crypto_box_seal);
Datum
pgsodium_crypto_box_seal (PG_FUNCTION_ARGS)
{
	bytea      *message;
	bytea      *public_key;
	size_t      result_size;
	bytea      *result;

	ERRORIF (PG_ARGISNULL (0), "%s: message cannot be NULL");
	ERRORIF (PG_ARGISNULL (1), "%s: publickey cannot be NULL");

	message = PG_GETARG_BYTEA_PP (0);
	public_key = PG_GETARG_BYTEA_PP (1);

	ERRORIF (VARSIZE_ANY_EXHDR (public_key) != crypto_box_PUBLICKEYBYTES,
		"%s: invalid public key");
	result_size = crypto_box_SEALBYTES + VARSIZE_ANY(message);
	result = _pgsodium_zalloc_bytea (result_size);
	crypto_box_seal (
		PGSODIUM_UCHARDATA (result),
		PGSODIUM_UCHARDATA_ANY (message),
		VARSIZE_ANY_EXHDR (message),
		PGSODIUM_UCHARDATA_ANY (public_key));
	PG_RETURN_BYTEA_P (result);
}
