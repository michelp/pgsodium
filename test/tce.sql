BEGIN;
SELECT plan(9);

CREATE SCHEMA private;

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON SCHEMA private IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'schemas cannot be labled');

CREATE TABLE private.bar(
  id bigserial,
  secret text,
  key_id uuid
);

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'tables cannot be labeled');

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret IS 'ENCRYPT WITH KEY ID key_id'
  $test$,
  'can label column for encryption');

SELECT id as secret_key_id FROM pgsodium.create_key('aead-det', 'Test Key') \gset

CREATE ROLE bobo;
GRANT USAGE ON SCHEMA private TO bobo;

SET ROLE bobo;

select throws_ok(
  format(
    $test$
    INSERT INTO private.bar (secret, key_id) values ('s3kr3t', %L);
    $test$, :'secret_key_id'),
    '42501',
    'permission denied for table bar',
    'test role cannot insert into labled table.'
);

RESET ROLE;

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON ROLE bobo is 'ACCESS private.bar'
  $test$,
  'can label roles ACCESS');

SET ROLE bobo;

select throws_ok(
  format(
    $test$
    INSERT INTO private.bar (secret, key_id) values ('s3kr3t', %L);
    $test$, :'secret_key_id'),
    '42501',
    'permission denied for table bar',
    'test role cannot insert into labled table.'
);

SELECT lives_ok(
  format(
    $test$
    INSERT INTO bar (secret, key_id) values ('s3kr3t', %L);
    $test$, :'secret_key_id'),
    'can insert into masking view');

select throws_ok(
  format(
    $test$
    TABLE private.bar;
    $test$),
    '42501',
    'permission denied for table bar',
    'test role cannot select from labled table.'
);

SELECT lives_ok(
  format(
    $test$
    TABLE bar;
    $test$),
    'can select from masking view');

RESET ROLE;

DROP SCHEMA private CASCADE;
SELECT * FROM finish();
ROLLBACK;
