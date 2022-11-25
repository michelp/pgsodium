\if :serverkeys
BEGIN;
SELECT plan(4);

select * from :"extschema".create_key() \gset anon_det_key_

select results_eq(
  format($$select
  key_id is not null,
  key_context is not null,
  raw_key is null,
  parent_key is null,
  raw_key_nonce is null,
  name is null,
  key_type = 'aead-det'
  from %I.key where id = %L$$, :'extschema', :'anon_det_key_id'),
  'values (true, true, true, true, true, true, true)',
  'anon det key asserts');

select * from :"extschema".create_key('aead-det', 'foo') \gset foo_det_key_

select results_eq(
  format($$select
  key_id is not null,
  key_context is not null,
  raw_key is null,
  parent_key is null,
  raw_key_nonce is null,
  key_type = 'aead-det',
  name = 'foo'
  from %I.key where id = %L$$, :'extschema', :'foo_det_key_id'),
  'values (true, true, true, true, true, true, true)',
  'named det key asserts');


select * from :"extschema".crypto_auth_hmacsha256_keygen() as ext_hmac256_key \gset
select * from :"extschema".create_key('hmacsha256', 'stripe', raw_key:=:'ext_hmac256_key') \gset stripe_hmac256_key_

select results_eq(
  format($$select
  key_id is null,
  key_context is null,
  raw_key is not null,
  parent_key is not null,
  raw_key_nonce is not null,
  name = 'stripe',
  key_type = 'hmacsha256'
  from %I.key where id = %L$$, :'extschema', :'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'named ext key asserts');

select * from :"extschema".create_key(
     'hmacsha256', 'stripe2', parent_key:=:'anon_det_key_id', raw_key:=:'ext_hmac256_key') \gset stripe_hmac256_key_

select results_eq(
  format($$select
  key_id is null,
  key_context is null,
  raw_key is not null,
  parent_key = %L,
  raw_key_nonce is not null,
  name = 'stripe2',
  key_type = 'hmacsha256'
  from %I.key where id = %L$$, :'anon_det_key_id', :'extschema', :'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'ext key asserts');

select results_eq(
    format($$select name = 'stripe2' from %I.get_key_by_id(%L)$$, :'extschema', :'stripe_hmac256_key_id'),
    'values (true)',
    'get_key_by_id()');

select results_eq(format($$select name = 'stripe2' from %I.get_key_by_name('stripe2')$$, :'extschema'),
    'values (true)',
    'get_key_by_name()');

select set_eq(format($$select name from %I.get_named_keys()$$, :'extschema'),
    ARRAY['foo', 'OPTIONAL_NAME', 'Optional Name 2', 'stripe', 'stripe2'],
    'get_named_keys() no filter');

select set_eq(format($$select name from %I.get_named_keys('strip%%')$$, :'extschema'),
    ARRAY['stripe', 'stripe2'],
    'get_named_keys() with filter');

SELECT * FROM finish();
ROLLBACK;
\endif
