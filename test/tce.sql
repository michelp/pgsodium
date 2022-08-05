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
  associated text,
  secret2 text,
  nonce bytea,
  associated2 text,
  secret2_key_id uuid,
  nonce2 bytea
);

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'tables cannot be labeled');

-- Create a key id to use in the tests below
SELECT id AS secret_key_id FROM pgsodium.create_key('Optional Comment') \gset

-- Create a key id to use in the tests below
SELECT id AS secret2_key_id
  FROM pgsodium.create_key('Optional Comment 2') \gset

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret
         IS 'ENCRYPT WITH KEY ID %s ASSOCIATED associated NONCE nonce'
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
         IS 'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED associated2 NONCE nonce2'
  $test$),
  'can label another column for encryption');

SELECT * FROM finish();
COMMIT;

\c postgres bobo
  
BEGIN;
SELECT plan(2);

SELECT pgsodium.crypto_aead_det_noncegen() nonce \gset
SELECT pgsodium.crypto_aead_det_noncegen() nonce2 \gset

SELECT lives_ok(
  format(
    $test$
    INSERT INTO bar (secret, associated, nonce, secret2, associated2, nonce2, secret2_key_id)
    VALUES ('s3kr3t', 'alice was here', %L, 'shhh', 'bob was here', %L, %L::uuid);
    $test$,
    :'nonce',
    :'nonce2',
    :'secret2_key_id'),
    'can insert into base table');

SELECT results_eq(
    $$SELECT decrypted_secret = 's3kr3t' FROM bar$$,
    $$VALUES (true)$$,
    'can select from masking view');

SELECT * FROM finish();

\c postgres postgres
DROP SCHEMA private CASCADE;
\endif
