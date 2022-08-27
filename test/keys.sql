\if :serverkeys
BEGIN;
SELECT plan(4);

select * from pgsodium.create_key() \gset anon_det_key_

select results_eq(
  format($$select
  key_id is not null,
  key_context is not null,
  raw_key is null,
  parent_key is null,
  raw_key_nonce is null,
  name is null,
  key_type = 'aead-det'
  from pgsodium.key where id = %L$$, :'anon_det_key_id'),
  'values (true, true, true, true, true, true, true)',
  'anon det key asserts');

select * from pgsodium.create_key('aead-det', 'foo') \gset foo_det_key_

select results_eq(
  format($$select
  key_id is not null,
  key_context is not null,
  raw_key is null,
  parent_key is null,
  raw_key_nonce is null,
  key_type = 'aead-det',
  name = 'foo'
  from pgsodium.key where id = %L$$, :'foo_det_key_id'),
  'values (true, true, true, true, true, true, true)',
  'named det key asserts');


select * from pgsodium.crypto_auth_hmacsha256_keygen() as ext_hmac256_key \gset
select * from pgsodium.create_key('hmacsha256', 'stripe', raw_key:=:'ext_hmac256_key') \gset stripe_hmac256_key_

select results_eq(
  format($$select
  key_id is null,
  key_context is null,
  raw_key is not null,
  parent_key is not null,
  raw_key_nonce is not null,
  name = 'stripe',
  key_type = 'aead-det'
  from pgsodium.key where id = %L$$,:'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'ext key asserts');

select * from pgsodium.create_key(
     'hmacsha256', 'stripe2', parent_key:=:'anon_det_key_id', raw_key:=:'ext_hmac256_key') \gset stripe_hmac256_key_

select results_eq(
  format($$select
  key_id is null,
  key_context is null,
  raw_key is not null,
  parent_key = %L,
  raw_key_nonce is not null,
  name = 'stripe',
  key_type = 'aead-det'
  from pgsodium.key where id = %L$$, :'anon_det_key_id', :'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'ext key asserts');

SELECT * FROM finish();
ROLLBACK;
\endif
