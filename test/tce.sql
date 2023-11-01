\if :serverkeys

CREATE SCHEMA private;
CREATE SCHEMA "private-test";

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON SCHEMA private IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'schemas cannot be labled');

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON SCHEMA "private-test" IS 'nope'
  $test$,
  '0A000',
  'pgsodium provider does not support labels on this object',
  'quoted schema cannot be labled');

CREATE TABLE private.foo(
  id integer,
  secret text,
  secretbytes bytea,
  associated text default ''
);

CREATE TABLE "private-test"."foo-test"(
  "secret-test" text,
  "associated-test" text default ''
);

CREATE TABLE private.bar(
  id bigserial primary key,
  secret text,
  nonce bytea  DEFAULT pgsodium.crypto_aead_det_noncegen(),
  secret2 text,
  associated2 text,
  secret2_key_id uuid DEFAULT (pgsodium.create_key()).id,
  nonce2 bytea DEFAULT pgsodium.crypto_aead_det_noncegen()
);

CREATE TABLE "private-test"."bar-test"(
  "secret2-test" text,
  "associated2-test" text,
  "secret2_key_id-test" uuid DEFAULT (pgsodium.create_key()).id,
  "nonce2-test" bytea DEFAULT pgsodium.crypto_aead_det_noncegen()
);

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'wrong'
  $test$,
  '42602',
  '''wrong'' is not a valid label for a table',
  'reject bad label on a table');

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bar IS 'DECRYPT WITH VIEW private.other_bar'
  $test$,
  'tables can be labeled with alternate view');

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE "private-test"."bar-test" IS 'DECRYPT WITH VIEW "private-test"."other_bar-test"'
  $test$,
  'quoted tables can be labeled with quoted alternate view');

-- Create a key id to use in the tests below
SELECT id AS secret_key_id FROM pgsodium.create_key('aead-det', 'OPTIONAL_NAME') \gset

-- Create another key id to use in the tests below
SELECT id AS secret2_key_id
  FROM pgsodium.create_key('aead-det', 'Optional Name 2') \gset

SELECT throws_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON COLUMN private.foo.secret IS 'wrong again'
  $test$,
  '42602',
  '''wrong again'' is not a valid label for a column',
  'reject bad label on a column');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.foo.secret
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label string column for encryption');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.foo.secretbytes
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label bytea column for encryption');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret
         IS 'ENCRYPT WITH KEY ID %s ASSOCIATED (id) NONCE nonce'
         $test$, :'secret_key_id'),
  'can label another column on same table for encryption');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN "private-test"."foo-test"."secret-test"
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label quoted column for encryption');

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON ROLE bobo is 'ACCESS private.foo, private.bar, private-test.other_bar-test'
  $test$,
  'can label roles ACCESS');

SELECT pgsodium.update_masks(); -- labeling roles doesn't fire event trigger

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bar.secret2
         IS 'ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED (id, associated2) NONCE nonce2'
  $test$),
  'can label another column for encryption');

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN "private-test"."bar-test"."secret2-test"
         IS 'ENCRYPT WITH KEY COLUMN secret2_key_id-test ASSOCIATED (associated2-test) NONCE nonce2-test'
  $test$),
  'can label another quoted column for encryption');

GRANT ALL ON SCHEMA private to bobo;
GRANT SELECT ON ALL TABLES IN SCHEMA private to bobo;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA private TO bobo;

GRANT ALL ON SCHEMA "private-test" to bobo;
GRANT ALL ON ALL TABLES IN SCHEMA "private-test" to bobo;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA "private-test" TO bobo;

select pgsodium.update_masks();

select ok(has_table_privilege('bobo', 'private.bar', 'SELECT'),
	'user keeps privs after regeneration');

select ok(has_table_privilege('bobo', 'private.other_bar', 'SELECT'),
	'user keeps view select privs after regeneration');

select ok(has_table_privilege('bobo', 'private.other_bar', 'INSERT'),
	'user keeps view insert privs after regeneration');

select ok(has_table_privilege('bobo', 'private.other_bar', 'UPDATE'),
	'user keeps view update privs after regeneration');

select ok(has_table_privilege('bobo', 'private.other_bar', 'DELETE'),
	'user keeps view delete privs after regeneration');

SET pgsodium.enable_event_trigger = 'off';

CREATE TABLE private.fooz(
  secret text
);

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.fooz.secret
         IS 'ENCRYPT WITH KEY ID %s'
         $test$, :'secret_key_id'),
  'can label column for encryption with event trigger disabled');

SELECT hasnt_view('private', 'decrypted_fooz', 'Dynamic view was not created due to disabled event trigger.');

SELECT hasnt_trigger('private', 'fooz', 'fooz_encrypt_secret_trigger_secret',
    'Dynamic trigger was not created due to disabled event trigger.');

SELECT lives_ok(
    $test$SELECT pgsodium.update_mask('private.fooz'::regclass);$test$,
    'can manually create trigger and view with event trigger disabled.');

SELECT has_view('private', 'decrypted_fooz', 'Dynamic view was created manually.');

SELECT has_trigger('private', 'fooz', 'fooz_encrypt_secret_trigger_secret',
    'Dynamic trigger was created manually.');

RESET pgsodium.enable_event_trigger;

SET SESSION AUTHORIZATION bobo;
SET ROLE bobo;

SELECT pgsodium.crypto_aead_det_noncegen() nonce \gset
SELECT pgsodium.crypto_aead_det_noncegen() nonce2 \gset

SELECT lives_ok(
  format(
    $test$
    INSERT INTO private.decrypted_foo (id, secret) VALUES (1, 's3kr3t');
    $test$),
    'can insert string into decrypted view');

SELECT lives_ok(
  format(
    $test$
    INSERT INTO private.decrypted_foo (id, secretbytes) VALUES (2, 's3kr3t'::bytea);
    $test$),
    'can insert bytes into decrypted view');

SELECT throws_ok(
  format(
    $test$
    INSERT INTO private.decrypted_foo (id, secret) VALUES (3, '');
    $test$),
    'P0001',
    'Cannot encrypt empty string.',
    'cannot insert empty string into decrypted view');

SELECT throws_ok(
  format(
    $test$
    INSERT INTO private.decrypted_foo (id, secretbytes) VALUES (4, ''::bytea);
    $test$),
    'P0001',
    'Cannot encrypt empty bytes.',
    'cannot insert empty bytes into decrypted view');

SELECT lives_ok(
  format(
    $test$
    UPDATE private.decrypted_foo SET secret  = 'sp00n' WHERE id = 1;
    $test$),
    'can update string into decrypted view');

SELECT results_eq($$SELECT decrypted_secret = 'sp00n' from private.decrypted_foo WHERE id = 1$$,
    $$VALUES (true)$$,
    'can see updated string in decrypted view');

SELECT lives_ok(
  format(
    $test$
    UPDATE private.decrypted_foo SET secretbytes  = 'sp00nb' WHERE id = 2;
    $test$),
    'can update bytes into decrypted view');

SELECT results_eq($$SELECT decrypted_secretbytes = 'sp00nb' from private.decrypted_foo WHERE id = 2$$,
    $$VALUES (true)$$,
    'can see updated bytes in decrypted view');

SELECT lives_ok(
    $test$
    INSERT INTO private.other_bar (secret, secret2, associated2)
    VALUES ('s3kr3t', 's3kr3t2', 'bob was here 2');
    $test$,
    'can insert into other bar');

SELECT lives_ok(
    $test$
    INSERT INTO "private-test"."bar-test" ("secret2-test", "associated2-test")
    VALUES ('s3kr3t-test', 'bob was here');
    $test$,
    'can insert into quoted private bar');

SELECT results_eq(
    $$SELECT decrypted_secret = 's3kr3t', decrypted_secret2 = 's3kr3t2' FROM private.other_bar$$,
    $$VALUES (true, true)$$,
    'can select from masking view');

SELECT lives_ok(
    $test$
    UPDATE private.other_bar SET secret = 'fooz';
    $test$,
    'can update one secret without effecting the other');

SELECT results_eq(
    $$SELECT decrypted_secret = 'fooz', decrypted_secret2 = 's3kr3t2' FROM private.other_bar$$,
    $$VALUES (true, true)$$,
    'can select from masking view');

SELECT results_eq(
    $$SELECT "decrypted_secret2-test" = 's3kr3t-test' FROM "private-test"."other_bar-test"$$,
    $$VALUES (true)$$,
    'can select from quoted masking view');

SELECT id AS another_secret_key_id FROM pgsodium.create_key(name:='ANOTHER_NAME') \gset

SELECT lives_ok(
  format(
    $test$
    UPDATE private.other_bar SET secret2 = decrypted_secret2, secret2_key_id = %L::uuid;
    $test$, :'another_secret_key_id'),
    'can update key id with rotation into decrypted view');

SELECT results_eq($$SELECT decrypted_secret2 = 's3kr3t2' from private.other_bar$$,
    $$VALUES (true)$$,
    'can see updated key id in decrypted view');

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


CREATE TABLE private.bobo(
  secret text,
  associated text
);

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON TABLE private.bobo IS 'DECRYPT WITH VIEW private.barbo'
  $test$,
  'non extension owner can label a table');

SELECT id AS bobo_key_id FROM pgsodium.create_key('aead-det', 'Bobo key') \gset

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN private.bobo.secret
         IS 'ENCRYPT WITH KEY ID %s ASSOCIATED (associated)'
         $test$, :'bobo_key_id'),
  'non extension owner can label column for encryption');

SELECT lives_ok(
  format(
    $test$
    INSERT INTO private.barbo (secret, associated) VALUES ('s3kr3t', 'it really really is');
    $test$),
    'can insert into non extension owner table');

SELECT results_eq(
    $$SELECT decrypted_secret = 's3kr3t' FROM private.barbo$$,
    $$VALUES (true)$$,
    'non-extension owner role can select from masking view');

SELECT lives_ok(
    $test$
    select pgsodium.update_masks()
    $test$,
    'can update only objects owned by session user');

RESET ROLE;
RESET SESSION AUTHORIZATION;

DROP SCHEMA private CASCADE;
\endif
