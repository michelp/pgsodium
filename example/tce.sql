CREATE SCHEMA IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

CREATE TABLE test (
  id bigserial primary key,
  secret text);

SELECT 'ENCRYPT WITH KEY ID ' || id AS seclabel
  FROM pgsodium.create_key('aead-det', 'Optional Comment') \gset

SECURITY LABEL FOR pgsodium
	ON COLUMN test.secret
                 IS :'seclabel';

insert into public.test (secret) values ('sssh');

-- SECURITY LABEL FOR pgsodium
-- 	ON COLUMN "user".secret
--   IS 'ENCRYPT WITH KEY COLUMN key_id';
