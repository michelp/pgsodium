BEGIN;
SELECT plan(1);

SELECT crypto_secretstream_keygen() streamkey \gset

ROLLBACK;
