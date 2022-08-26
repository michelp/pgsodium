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

CREATE TABLE private.foo(
  secret text,
  associated text
);

CREATE TABLE private.bar(
  id bigserial primary key,
  secret text,
  nonce bytea,
  secret2 text,
  associated2 text,
  secret2_key_id uuid,
  nonce2 bytea
);

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'DECRYPT WITH VIEW private.other_bar'
  $test$,
  'tables can be labeled with alternate view');


-- Create a key id to use in the tests below
SELECT id AS secret_key_id FROM pgsodium.create_key('aead-det', 'OPTIONAL_NAME') \gset

-- Create a key id to use in the tests below
SELECT id AS secret2_key_id
  FROM pgsodium.create_key('aead-det', 'Optional Name 2') \gset

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.foo.secret
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label column for encryption');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret
         IS 'ENCRYPT WITH KEY ID %s ASSOCIATED (id) NONCE nonce'
         $test$, :'secret_key_id'),
  'can label column for encryption');

CREATE ROLE bobo with login password 'foo';

GRANT USAGE ON SCHEMA private to bobo;
GRANT SELECT ON TABLE private.foo to bobo;
GRANT SELECT ON TABLE private.bar to bobo;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA private TO bobo;

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON ROLE bobo is 'ACCESS private.foo, private.bar'
  $test$,
  'can label roles ACCESS');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret2
         IS 'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED (id, associated2) NONCE nonce2'
  $test$),
  'can label another column for encryption');

SELECT * FROM finish();
COMMIT;

\c postgres bobo

BEGIN;
SELECT plan(4);

SELECT pgsodium.crypto_aead_det_noncegen() nonce \gset
SELECT pgsodium.crypto_aead_det_noncegen() nonce2 \gset

SELECT lives_ok(
  format(
    $test$
    INSERT INTO private.decrypted_foo (secret) VALUES ('s3kr3t');
    $test$),
    'can insert into foo table');

SELECT lives_ok(
  format(
    $test$
    INSERT INTO private.other_bar (secret, nonce, secret2, associated2, nonce2, secret2_key_id)
    VALUES ('s3kr3t', %L, 'shhh', 'bob was here', %L, %L::uuid);
    $test$,
    :'nonce',
    :'nonce2',
    :'secret2_key_id'),
    'can insert into bar table');

SELECT results_eq(
    $$SELECT decrypted_secret = 's3kr3t' FROM private.decrypted_foo$$,
    $$VALUES (true)$$,
    'can select from masking view');

SELECT results_eq(
    $$SELECT decrypted_secret = 's3kr3t' FROM private.other_bar$$,
    $$VALUES (true)$$,
    'can select from masking view');

SELECT * FROM finish();

\c postgres postgres
DROP SCHEMA private CASCADE;
COMMIT;
\endif
