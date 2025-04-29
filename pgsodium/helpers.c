#include "pgsodium.h"

PG_FUNCTION_INFO_V1 (pgsodium_cmp);
Datum
pgsodium_cmp (PG_FUNCTION_ARGS)
{
	int         i = 0;
	int         m = 0;

	bytea      *X = PG_GETARG_BYTEA_PP (0);
	bytea      *Y = PG_GETARG_BYTEA_PP (1);
	size_t      xlen = VARSIZE_ANY (X);
	size_t      ylen = VARSIZE_ANY (Y);
	char       *x = VARDATA_ANY (X);
	char       *y = VARDATA_ANY (Y);

	if (xlen != ylen)
		PG_RETURN_BOOL (false);

	for (i = 0; i < xlen; i++)
		m |= x[i] ^ y[i];

	PG_RETURN_BOOL (m == 0);
}

PG_FUNCTION_INFO_V1 (pgsodium_sodium_bin2base64);
Datum
pgsodium_sodium_bin2base64 (PG_FUNCTION_ARGS)
{
	bytea      *bin;
	size_t      bin_size;
	size_t      text_size;
	text       *base64;

	ERRORIF (PG_ARGISNULL (0), "%s: bin cannot be NULL");

	bin = PG_GETARG_BYTEA_PP (0);
	bin_size = VARSIZE_ANY_EXHDR (bin);
	text_size = sodium_base64_ENCODED_LEN (
		bin_size,
		sodium_base64_VARIANT_URLSAFE_NO_PADDING);
	base64 = (text *) _pgsodium_zalloc_text (text_size + VARHDRSZ);

	sodium_bin2base64 (
		PGSODIUM_CHARDATA (base64),
		text_size,
		PGSODIUM_UCHARDATA_ANY (bin),
		bin_size,
		sodium_base64_VARIANT_URLSAFE_NO_PADDING);
	PG_RETURN_TEXT_P (base64);
}

PG_FUNCTION_INFO_V1 (pgsodium_sodium_base642bin);
Datum
pgsodium_sodium_base642bin (PG_FUNCTION_ARGS)
{
	text       *base64;
	size_t      base64_size;
	size_t      max_bin_size;
	bytea      *bin;
	size_t      bin_size;
	int         success;

	ERRORIF (PG_ARGISNULL (0), "%s: base64 cannot be NULL");

	base64 = PG_GETARG_TEXT_PP (0);
	base64_size = VARSIZE_ANY_EXHDR (base64);
	max_bin_size = ((base64_size + 1) / 4) * 3;
	bin = _pgsodium_zalloc_bytea (max_bin_size + VARHDRSZ);

	success = sodium_base642bin (
		PGSODIUM_UCHARDATA (bin),
		max_bin_size,
		PGSODIUM_CHARDATA_ANY (base64),
		base64_size,
		"",
		&bin_size,
		NULL,
		sodium_base64_VARIANT_URLSAFE_NO_PADDING);
	ERRORIF (success != 0, "%s: sodium_base642bin() failed");
	SET_VARSIZE (bin, bin_size + VARHDRSZ);
	PG_RETURN_BYTEA_P (bin);
}
