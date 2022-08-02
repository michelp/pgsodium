CREATE SCHEMA IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium CASCADE;

CREATE TABLE test (
  secret text,
  associated text,
  secret2 text,
  associated2 text,
  secret2_key_id uuid);

CREATE ROLE bob with login password 'foo';

SECURITY LABEL FOR pgsodium ON ROLE bob is 'ACCESS public.test';

SELECT format('ENCRYPT WITH KEY ID %s ASSOCIATED associated',
              (pgsodium.create_key('aead-det', 'Optional Comment for Secret Key')).id) AS seclabel \gset

SELECT id AS secret2_key_id FROM pgsodium.create_key('aead-det', 'Comment for Secret2 Key') \gset

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret IS :'seclabel';

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret2 IS
                 'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED associated2';

INSERT INTO public.test (secret, associated, secret2, associated2, secret2_key_id)
    VALUES ('sssh', 'bob was here', 'aaahh', 'alice association', :'secret2_key_id'::uuid);

