#include "pgsodium.h"

PG_MODULE_MAGIC;

bytea *pgsodium_secret_key;
static char *getkey_script = NULL;

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

    if (process_shared_preload_libraries_in_progress) {
        path = (char *)malloc(MAXPGPATH);
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
}
