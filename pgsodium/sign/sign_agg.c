#include "pgsodium.h"

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
