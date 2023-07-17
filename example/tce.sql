\set ON_ERROR_ROLLBACK 0
\set ON_ERROR_STOP on
\set ECHO all

CREATE EXTENSION IF NOT EXISTS pgsodium;

DROP SCHEMA IF EXISTS "tce-example" CASCADE;
CREATE SCHEMA "tce-example";

SET search_path = "tce-example", pg_catalog;

CREATE TABLE test (
  secret text,
  name text unique
);

CREATE TABLE test2 (
  id bigserial primary key,
  secret bytea,
  associated text,
  nonce bytea,
  secret2 text,
  associated2 text,
  secret2_key_id uuid,
  nonce2 bytea
);

CREATE ROLE bob with login password 'foo';
GRANT INSERT ON "tce-example".test, "tce-example".test2 to bob;
GRANT USAGE ON SEQUENCE test2_id_seq to bob;

SECURITY LABEL FOR pgsodium ON ROLE bob is 'ACCESS "tce-example".test, "tce-example".test2';

SELECT format('ENCRYPT WITH KEY ID %s', (pgsodium.create_key('aead-det')).id)
    AS seclabel \gset

SELECT format('ENCRYPT WITH KEY ID %s ASSOCIATED (associated) NONCE nonce', (
    pgsodium.create_key('aead-det')).id) AS seclabel2 \gset

SELECT id AS secret2_key_id FROM pgsodium.create_key('aead-det', 'foo_key') \gset

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret IS :'seclabel';

SECURITY LABEL FOR pgsodium ON TABLE "tce-example".test2 IS
    'DECRYPT WITH VIEW "tce-example"."other-test2"';

SECURITY LABEL FOR pgsodium	ON COLUMN test2.secret IS :'seclabel2';

SECURITY LABEL FOR pgsodium	ON COLUMN "tce-example".test2.secret2 IS
    'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED (id, associated2) NONCE nonce2';

SELECT pgsodium.crypto_aead_det_noncegen() aead_nonce \gset
SELECT pgsodium.crypto_aead_det_noncegen() aead_nonce2 \gset

GRANT ALL ON SCHEMA "tce-example" TO bob;
select pgsodium.update_masks(true);

COMMIT;
\c postgres bob
\x

SET search_path = "tce-example", pg_catalog;

INSERT INTO "tce-example".decrypted_test (secret) VALUES ('noice') RETURNING *;

INSERT INTO "tce-example"."other-test2" (secret, associated, nonce, secret2, associated2, nonce2, secret2_key_id)
    VALUES ('sssh', 'bob was here', :'aead_nonce', 'aaahh', 'alice association', :'aead_nonce2', :'secret2_key_id'::uuid) RETURNING *;

CREATE TABLE "tce-example"."bob-testt" (
  "secret2-test" text,
  "associated2-test" text,
  "secret2_key_id-test" uuid DEFAULT (pgsodium.create_key()).id,
  "nonce2-test" bytea DEFAULT pgsodium.crypto_aead_det_noncegen()
);

SECURITY LABEL FOR pgsodium	ON COLUMN "bob-testt"."secret2-test" IS
    'ENCRYPT WITH KEY COLUMN secret2_key_id-test ASSOCIATED (associated2-test) NONCE nonce2-test SECURITY INVOKER';

select pgsodium.update_masks(true);
