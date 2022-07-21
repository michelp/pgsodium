#include "pgsodium.h"

PG_MODULE_MAGIC;

bytea *pgsodium_secret_key;
static char *getkey_script = NULL;

/*
 * Checking the syntax of the masking rules
 */
static void
pgsodium_object_relabel(const ObjectAddress *object, const char *seclabel)
{
  /* SECURITY LABEL FOR pgsodium ON COLUMN foo.bar IS NULL */
  if (seclabel == NULL) return;

  switch (object->classId)
  {
    case RelationRelationId:

      /* SECURITY LABEL FOR pgsodium ON TABLE ...' */
      if (object->objectSubId == 0)
        ereport(ERROR,
          (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
           errmsg("pgsodium provider does not support labels on this object")));

      /* SECURITY LABEL FOR pgsodium ON COLUMN t.i IS '...' */
      if ( pg_strncasecmp(seclabel, "ENCRYPT WITH", 12) == 0)
        return;

      ereport(ERROR,
        (errcode(ERRCODE_INVALID_NAME),
         errmsg("'%s' is not a valid label for a column", seclabel)));
      break;

    /* SECURITY LABEL FOR pgsodium ON ROLE sodium_user IS 'MASKED' */
    case AuthIdRelationId:
        if (pg_strncasecmp(seclabel,"ACCESS", 6) == 0)
        return;

      ereport(ERROR,
        (errcode(ERRCODE_INVALID_NAME),
         errmsg("'%s' is not a valid label for a role", seclabel)));
      break;

    /* /\* SECURITY LABEL FOR pgsodium ON SCHEMA public IS 'TRUSTED' *\/ */
    /* case NamespaceRelationId: */
    /*   if (!superuser()) */
    /*     ereport(ERROR, */
    /*         (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), */
    /*          errmsg("only superuser can set a pgsodium label for a schema"))); */

    /*   if (pg_strcasecmp(seclabel,"TRUSTED") == 0) */
    /*     return; */

    /*   ereport(ERROR, */
    /*     (errcode(ERRCODE_INVALID_NAME), */
    /*      errmsg("'%s' is not a valid label for a schema", seclabel))); */
    /*   break; */

    /* everything else is unsupported */
    default:
      ereport(ERROR,
          (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
           errmsg("pgsodium provider does not support labels on this object")));
      break;
  }

  ereport(ERROR,
      (errcode(ERRCODE_INVALID_NAME),
       errmsg("'%s' is not a valid label", seclabel)));
}


void _PG_init(void) {
    FILE *fp;
    char *secret_buf;
    size_t secret_len = 0;
    size_t char_read;
    char *path;
    char sharepath[MAXPGPATH];

    if (sodium_init() == -1) {
        elog(ERROR,
             "_PG_init: sodium_init() failed cannot initialize pgsodium");
        return;
    }

    /* Security label provider hook */
    register_label_provider("pgsodium", pgsodium_object_relabel);
  
    // we're done if not preloaded, otherwise try to get internal shared key
	if (!process_shared_preload_libraries_in_progress)
		return;

    path = (char *)palloc0(MAXPGPATH);
    get_share_path(my_exec_path, sharepath);
    snprintf(path, MAXPGPATH, "%s/extension/%s", sharepath, PG_GETKEY_EXEC);
    DefineCustomStringVariable(
        "pgsodium.getkey_script",
        "path to script that returns pgsodium root key",
        NULL,
        &getkey_script,
        path,
        PGC_POSTMASTER,
        0,
        NULL,
        NULL,
        NULL);

    if (access(getkey_script, F_OK) == -1) {
        fprintf(stderr, "Permission denied for %s\n", getkey_script);
        proc_exit(1);
    }

    if ((fp = popen(getkey_script, "r")) == NULL) {
        fprintf(stderr,
                "%s: could not launch shell command from\n",
                getkey_script);
        proc_exit(1);
    }

    char_read = getline(&secret_buf, &secret_len, fp);
    if (secret_buf[char_read - 1] == '\n')
        secret_buf[char_read - 1] = '\0';

    secret_len = strlen(secret_buf);

    if (secret_len != 64) {
        fprintf(stderr, "invalid secret key\n");
        proc_exit(1);
    }

    if (pclose(fp) != 0) {
        fprintf(
            stderr, "%s: could not close shell command\n", PG_GETKEY_EXEC);
        proc_exit(1);
    }
    pgsodium_secret_key =
        sodium_malloc(crypto_sign_SECRETKEYBYTES + VARHDRSZ);

    if (pgsodium_secret_key == NULL) {
        fprintf(stderr, "%s: sodium_malloc() failed\n", PG_GETKEY_EXEC);
        proc_exit(1);
    }

    hex_decode(secret_buf, secret_len, VARDATA(pgsodium_secret_key));
    sodium_memzero(secret_buf, secret_len);
    free(secret_buf);
}
