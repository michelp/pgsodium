-- CREATE SCHEMA IF NOT EXISTS pgsodium;
-- CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

CREATE TABLE "user" (
  id bigserial primary key,
  key_id uuid,
  secret text);

SELECT 'ENCRYPT WITH KEY ID ' || id AS seclabel
  FROM pgsodium.create_key('aead-det', 'Optional Comment') \gset

-- SECURITY LABEL FOR pgsodium
-- 	ON COLUMN private.users.secret
--   IS :'seclabel';

-- SECURITY LABEL FOR pgsodium
-- 	ON COLUMN "user".secret
--   IS 'ENCRYPT WITH KEY COLUMN key_id';
