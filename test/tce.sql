\if :serverkeys
BEGIN;
SELECT plan(6);

CREATE SCHEMA private;

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON SCHEMA private IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'schemas cannot be labled');

CREATE TABLE private.bar(
  secret text,
  secret2 text,
  secret2_key_id uuid
);

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'tables cannot be labeled');

-- Create a key id to use in the tests below
SELECT id AS secret_key_id
  FROM pgsodium.create_key('aead-det', 'Optional Comment') \gset

-- Create a key id to use in the tests below
SELECT id AS secret2_key_id
  FROM pgsodium.create_key('aead-det', 'Optional Comment') \gset

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label column for encryption');

CREATE ROLE bobo with login password 'foo';

GRANT USAGE ON SCHEMA private to bobo;
GRANT SELECT ON TABLE private.bar to bobo;

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON ROLE bobo is 'ACCESS private.bar'
  $test$,
  'can label roles ACCESS');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret2
         IS 'ENCRYPT WITH KEY COLUMN secret2_key_id'
  $test$),
  'can label another column for encryption');

SELECT * FROM finish();
COMMIT;

\c postgres bobo
  
BEGIN;
SELECT plan(2);

SELECT lives_ok(
  format(
    $test$
    INSERT INTO bar (secret, secret2, secret2_key_id)
    VALUES ('s3kr3t', 'shhh', %L::uuid);
    $test$,
    :'secret2_key_id'),
    'can insert into base table');

SELECT lives_ok(
  format(
    $test$
    TABLE bar;
    $test$),
    'can select from masking view');

SELECT * FROM finish();

\c postgres postgres
DROP SCHEMA private CASCADE;
\endif
