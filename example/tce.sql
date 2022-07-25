CREATE SCHEMA IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

CREATE TABLE test (
  id bigserial primary key,
  secret text,
  secret2 text);

CREATE ROLE bob with login password 'foo';
SECURITY LABEL FOR pgsodium ON ROLE bob is 'ACCESS public.test';

SELECT 'ENCRYPT WITH KEY ID ' || id AS seclabel
  FROM pgsodium.create_key('aead-det', 'Optional Comment') \gset

SECURITY LABEL FOR pgsodium	ON COLUMN test.secret IS :'seclabel';
SECURITY LABEL FOR pgsodium	ON COLUMN test.secret2 IS :'seclabel';

INSERT INTO public.test (secret, secret2) values ('sssh', 'aaahh');

