\set ON_ERROR_ROLLBACK 0
\set ON_ERROR_STOP on
\set ECHO all

CREATE EXTENSION IF NOT EXISTS pgsodium;

CREATE TABLE test (
  secret text
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
GRANT INSERT ON public.test, public.test2 to bob;
GRANT USAGE ON SEQUENCE test2_id_seq to bob;

SECURITY LABEL FOR pgsodium ON ROLE bob is 'ACCESS public.test, public.test2';

SELECT format('ENCRYPT WITH KEY ID %s', (pgsodium.create_key('aead-det')).id)
    AS seclabel \gset

SELECT format('ENCRYPT WITH KEY ID %s ASSOCIATED (associated) NONCE nonce', (
    pgsodium.create_key('aead-det')).id) AS seclabel2 \gset

SELECT id AS secret2_key_id FROM pgsodium.create_key('aead-det', 'foo_key') \gset

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret IS :'seclabel';

SECURITY LABEL FOR pgsodium ON TABLE public.test2 IS
    'DECRYPT WITH VIEW public.other_test2';

SECURITY LABEL FOR pgsodium	ON COLUMN test2.secret IS :'seclabel2';

SECURITY LABEL FOR pgsodium	ON COLUMN public.test2.secret2 IS
    'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED (id, associated2) NONCE nonce2';

SELECT pgsodium.crypto_aead_det_noncegen() aead_nonce \gset
SELECT pgsodium.crypto_aead_det_noncegen() aead_nonce2 \gset

\c postgres bob
\x
         
INSERT INTO decrypted_test (secret) VALUES ('noice') RETURNING *;

INSERT INTO other_test2 (secret, associated, nonce, secret2, associated2, nonce2, secret2_key_id)
    VALUES ('sssh', 'bob was here', :'aead_nonce', 'aaahh', 'alice association', :'aead_nonce2', :'secret2_key_id'::uuid) RETURNING *;
