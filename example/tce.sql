CREATE SCHEMA IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

CREATE TABLE test (
  id bigserial primary key,
  secret text,
  secret2 text,
  secret2_key_id uuid);

CREATE ROLE bob with login password 'foo';
SECURITY LABEL FOR pgsodium ON ROLE bob is 'ACCESS public.test';

SELECT 'ENCRYPT WITH KEY ID ' || id AS seclabel
  FROM pgsodium.create_key('aead-det', 'Optional Comment for Secret Key') \gset

SELECT id AS secret2_key_id FROM pgsodium.create_key('aead-det', 'Comment for Secret2 Key') \gset

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret IS :'seclabel';
SECURITY LABEL FOR pgsodium	ON COLUMN test.secret2 IS  'ENCRYPT WITH KEY COLUMN secret2_key_id';

INSERT INTO public.test (secret, secret2, secret2_key_id)
    VALUES ('sssh', 'aaahh', :'secret2_key_id'::uuid);

