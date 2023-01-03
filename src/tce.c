#include "pgsodium.h"
#include "executor/spi.h"
#include "parser/parse_type.h"
#include "lib/stringinfo.h"
#include "utils/lsyscache.h"

static void fetch_key_meta_using_uuid(Datum keyuuid, Datum *key_id,
									  Datum *key_context)
{
	int ret;
	Oid uuidtype; /* uuidtype */
	bool isnull;
	HeapTuple rettuple  = NULL;

	/*
	 * Connect to SPI manager.
	 * Every operations now occurs in the SPI memory context!
	 */
	if ((ret = SPI_connect()) < 0)
		/* internal error */
		elog(ERROR, "fetch_key_meta_using_uuid: SPI_connect returned %d", ret);

	// FIXME: error when not found
	parseTypeString("uuid", &uuidtype, NULL, false);

	/* Fetch key_id and key_context from pgsodium key table */
	ret = SPI_execute_with_args(
		"SELECT key_id, key_context    "
		"FROM pgsodium.decrypted_key v "
		"WHERE id = $1                 "
		"  AND key_type = 'aead-det'   ",
		1,  &uuidtype, &keyuuid, NULL, true, 1
	);

	if (ret < 0)
		elog(ERROR,
			 "fetch_key_meta_using_uuid: SPI_execute_with_args returned %d",
			 ret);

	if (ret != SPI_OK_SELECT)
		elog(ERROR,
			 "fetch_key_meta_using_uuid: unexpected query result (return: %d)",
			 ret);

	if (SPI_processed > 1)
		elog(ERROR, "more than one key found for uuid %s",
			 DatumGetCString(DirectFunctionCall1(uuid_out, keyuuid)));

	if (SPI_processed == 0)
		elog(ERROR, "no key found for uuid %s",
			 DatumGetCString(DirectFunctionCall1(uuid_out, keyuuid)));

	rettuple = SPI_copytuple(SPI_tuptable->vals[0]);

	/* Get key_id Datum from the query result */
	*key_id = SPI_getbinval(rettuple, SPI_tuptable->tupdesc, 1, &isnull);
	if (isnull)
		elog(ERROR, "key found for uuid %s is NULL",
			 DatumGetCString(DirectFunctionCall1(uuid_out, keyuuid)));

	/* Get key_context Datum from the query result */
	*key_context = SPI_getbinval(rettuple, SPI_tuptable->tupdesc, 2, &isnull);
	if (isnull)
		elog(ERROR, "key context for uuid %s is NULL",
			 DatumGetCString(DirectFunctionCall1(uuid_out, keyuuid)));

	SPI_finish();
}
/**** Trigger related code ****/

/*
 * Common code between tg_tce_encrypt_using_key_id() and
 * tg_tce_encrypt_using_key_col().
 */
static Datum tg_tce_encrypt(PG_FUNCTION_ARGS, Datum keyuuid)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;

	Trigger    *trigger	  = trigdata->tg_trigger;	/* to get trigger name */
	Relation	rel		  = trigdata->tg_relation;	/* triggered relation */
	char	  **tgargs	  = trigger->tgargs;		/* trigger arguments */
	TupleDesc	tupdesc	  = rel->rd_att;			/* tuple description */
	HeapTuple	rettuple  = NULL;

	int			msgattnum;	/* message attribute position in row */
	Datum		message;	/* non encrypted message */
	Datum		encmsg;		/* encrypted message */

	Datum		key_id;		/* key_id from pgsodium.key */
	Datum		key_context;	/* key context from pgsodium.key */

	bool		isnull = false;
	bool		istext = false;

	/* func call info for pgsodium_crypto_aead_det_encrypt_by_id */
	LOCAL_FCINFO(fcencinfo, 5);

	if (TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
		rettuple = trigdata->tg_trigtuple;
	else if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
		rettuple = trigdata->tg_newtuple;

	/* get message Datum from the tuple */
	msgattnum = SPI_fnumber(tupdesc, tgargs[0]); // FIXME test return value
	message = SPI_getbinval(rettuple, tupdesc, msgattnum, &isnull);
	/* No encryption if the field to encrypt is NULL */
	if (isnull)
		return PointerGetDatum(rettuple);

	istext = (SPI_gettypeid(tupdesc, msgattnum) == TEXTOID);

	/* if the message type is text, convert it to bytea */
	if (istext)
		message = DirectFunctionCall2(pg_convert_to, message,
									  CStringGetDatum("utf8"));

	fetch_key_meta_using_uuid(keyuuid, &key_id, &key_context);

	/* init fields of the function call structs */
	InitFunctionCallInfoData(*fcencinfo, NULL, 5, InvalidOid, NULL, NULL);

	/* set function call args */
	/* arg 1: message to encrypt */
	fcencinfo->args[0].value = message;
	fcencinfo->args[0].isnull = false;

	/* arg 2: associated data if any */
	if (trigger->tgnargs > 3)
	{
		int	i;
		StringInfoData assocdata;

		initStringInfo(&assocdata);

		for (i=3; i < trigger->tgnargs; i++)
		{
			int assocattnum = SPI_fnumber(tupdesc, tgargs[i]); // FIXME: test return value
			Oid assocatttyp = SPI_gettypeid(tupdesc, assocattnum); // FIXME: test return value
			Oid assocattfout;
			Datum value;

			getTypeOutputInfo(assocatttyp, &assocattfout, &isnull); // FIXME: test if fout is valid

			value = SPI_getbinval(rettuple, tupdesc, assocattnum, &isnull);

			if (isnull)
				continue;

			appendStringInfoString(&assocdata,
								   OidOutputFunctionCall(assocattfout, value));
		}

		fcencinfo->args[1].value = PointerGetDatum(
					cstring_to_text_with_len(assocdata.data, assocdata.len));
		fcencinfo->args[1].isnull = false;
	}
	else
	{
		fcencinfo->args[1].value = (Datum) 0;
		fcencinfo->args[1].isnull = true;
	}

	/* arg 3: key id */
	fcencinfo->args[2].value = key_id;
	fcencinfo->args[2].isnull = false;

	/* arg 4: key context */
	fcencinfo->args[3].value = key_context;
	fcencinfo->args[3].isnull = false;

	/* arg 5: nonce */
	if (trigger->tgnargs > 2 && *tgargs[2] != '\0')
	{
		int nonceattnum = SPI_fnumber(tupdesc, tgargs[2]); // FIXME test return value
		fcencinfo->args[4].value = SPI_getbinval(rettuple, tupdesc, nonceattnum, &isnull);
		fcencinfo->args[4].isnull = isnull;
	}
	else
	{
		fcencinfo->args[4].value = (Datum) 0;
		fcencinfo->args[4].isnull = true;
	}

	/* encrypt the message */
	encmsg = pgsodium_crypto_aead_det_encrypt_by_id(fcencinfo);

	/* if the field type is text, convert the encrypted message to base64 */
	if (istext)
	{
		encmsg = DirectFunctionCall2(binary_encode, encmsg,
									  CStringGetTextDatum("base64"));
	}

	/* update the row to store with the encrypted message */
	isnull = false;
	rettuple = heap_modify_tuple_by_cols(rettuple, tupdesc, 1, &msgattnum,
										 &encmsg, &isnull);

	return PointerGetDatum(rettuple);
}

/*
 * This triggers arguments are:
 * - the field name to encrypt
 * - the field name holding the key uuid
 * - optionally the field name holding the nonce
 */
PG_FUNCTION_INFO_V1(tg_tce_encrypt_using_key_col);
Datum
tg_tce_encrypt_using_key_col(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;

	Trigger    *trigger	 = trigdata->tg_trigger;	/* to get trigger name */
	char	   *tgname	 = trigger->tgname;			/* trigger name */
	Relation	rel		 = trigdata->tg_relation;	/* triggered relation */
	char	   *relname  = RelationGetRelationName(rel); /* trig'ed relname */
	char	  **tgargs	 = trigger->tgargs;			/* trigger arguments */
	TupleDesc	tupdesc	 = rel->rd_att;				/* tuple description */
	HeapTuple	rettuple = NULL;

	Datum		keyuuid;
	int			keyattnum;

	bool		isnull = false;

	if (!CALLED_AS_TRIGGER(fcinfo))
		/* internal error */
		elog(ERROR,
			 "tg_tce_encrypt_using_key_col: not fired by trigger manager");

	if (!TRIGGER_FIRED_FOR_ROW(trigdata->tg_event))
		/* internal error */
		elog(ERROR, "%s on %s: must be fired for row", tgname, relname);

	if (!TRIGGER_FIRED_BEFORE(trigdata->tg_event))
		/* internal error */
		elog(ERROR, "%s on %s: must be fired before event", tgname, relname);

	if (TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
		rettuple = trigdata->tg_trigtuple;
	else if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
		rettuple = trigdata->tg_newtuple;
	else
		/* internal error */
		elog(ERROR, "%s on %s: cannot process DELETE events", tgname, relname);

	if (trigger->tgnargs < 2)
		/* internal error */
		elog(ERROR, "%s on %s: at least two arguments are expected",
			 tgname, relname);

	/* get key uuid Datum from the row */
	keyattnum = SPI_fnumber(tupdesc, tgargs[1]); // FIXME test return value
	keyuuid   = SPI_getbinval(rettuple, tupdesc, keyattnum, &isnull);

	/*
	 * Set field to NULL if the key uuid is NULL.
	 * FIXME: shouldn't we raise an ERROR instead?
	 */
	if (isnull)
	{
		Datum encmsg  = (Datum) 0;
		int msgattnum = SPI_fnumber(tupdesc, tgargs[0]); // FIXME test return value;

		rettuple = heap_modify_tuple_by_cols(rettuple, tupdesc,
											 1, &msgattnum,
											 &encmsg, &isnull);
		return PointerGetDatum(rettuple);
	}

	return tg_tce_encrypt(fcinfo, keyuuid);
}


/*
 * This triggers arguments are:
 * - the field name to encrypt
 * - the key uuid
 * - optionally the field name holding the nonce
 */
PG_FUNCTION_INFO_V1(tg_tce_encrypt_using_key_id);
Datum
tg_tce_encrypt_using_key_id(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;

	Trigger    *trigger	 = trigdata->tg_trigger;	/* to get trigger name */
	char	   *tgname	 = trigger->tgname;			/* trigger name */
	Relation	rel		 = trigdata->tg_relation;	/* triggered relation */
	char	   *relname  = RelationGetRelationName(rel); /* relation name */
	char	  **tgargs	 = trigger->tgargs;			/* trigger arguments */

	Datum		keyuuid;

	if (!CALLED_AS_TRIGGER(fcinfo))
		/* internal error */
		elog(ERROR,
			 "tg_tce_encrypt_using_key_id: not fired by trigger manager");

	if (!TRIGGER_FIRED_FOR_ROW(trigdata->tg_event))
		/* internal error */
		elog(ERROR, "%s on %s: must be fired for row", tgname, relname);

	if (!TRIGGER_FIRED_BEFORE(trigdata->tg_event))
		/* internal error */
		elog(ERROR, "%s on %s: must be fired before event", tgname, relname);

	if (trigger->tgnargs < 2)
		/* internal error */
		elog(ERROR, "%s on %s: at least two arguments are expected",
			 tgname, relname);

	/* this raise an error if the uuid is invalid */
	keyuuid = DirectFunctionCall1(uuid_in, CStringGetDatum(tgargs[1]));

	return tg_tce_encrypt(fcinfo, keyuuid);
}
