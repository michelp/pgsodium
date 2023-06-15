\if :serverkeys

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
  key_type = 'hmacsha256'
  from pgsodium.key where id = %L$$,:'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'named ext key asserts');

select * from pgsodium.create_key(
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
  from pgsodium.key where id = %L$$, :'anon_det_key_id', :'stripe_hmac256_key_id'),
  'values (true, true, true, true, true, true, true)',
  'ext key asserts');

select results_eq(
    format($$select name = 'stripe2' from pgsodium.get_key_by_id(%L)$$, :'stripe_hmac256_key_id'),
    'values (true)',
    'get_key_by_id()');

select results_eq($$select name = 'stripe2' from pgsodium.get_key_by_name('stripe2')$$,
    'values (true)',
    'get_key_by_name()');

select set_eq($$select name from pgsodium.get_named_keys()$$,
    ARRAY['foo', 'OPTIONAL_NAME', 'Optional Name 2', 'stripe',
    'stripe2', 'ANOTHER_NAME', 'Bobo key', 'ietf Test Key', 'det Test Key'],
    'get_named_keys() no filter');

select set_eq($$select name from pgsodium.get_named_keys('strip%')$$,
    ARRAY['stripe', 'stripe2'],
    'get_named_keys() with filter');

-- Test expiring keys
select set_eq($$select id IS NOT NULL from pgsodium.create_key(name => 'notexpired', expires => now() + '1h'::interval)$$,
    'values (true)',
    'creating a key expiring in one hour returns a row');

select id as exp_id from pgsodium.key where name = 'notexpired' \gset

select set_has($$select name from pgsodium.valid_key$$, $$values ('notexpired'::text)$$,
    'view valid_key should list a key expiring in futur');

select set_eq(format('select id from pgsodium.get_key_by_id(%L)', :'exp_id' ),
    format($$values (%L::uuid)$$, :'exp_id'),
    'pgsodium.get_key_by_id should return a key expiring in futur');

select set_eq($$select id from pgsodium.get_key_by_name('notexpired')$$,
    format($$values (%L::uuid)$$, :'exp_id'),
    'pgsodium.get_key_by_name should return a key expiring in futur');

update pgsodium.key set expires = now() - '1m'::interval, name = 'expired' where name = 'notexpired';

select set_hasnt($$select name from pgsodium.valid_key$$, $$values ('expired'::text)$$,
    'view valid_key should not list an expired key');

select set_eq(format('select id IS NULL from pgsodium.get_key_by_id(%L)', :'exp_id' ),
    'values (true)',
    'pgsodium.get_key_by_id should not return an expired key');

select set_eq($$select id IS NULL from pgsodium.get_key_by_name('expired')$$,
    'values (true)',
    'pgsodium.get_key_by_name should not return an expired key');

\endif
