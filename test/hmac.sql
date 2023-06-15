
select crypto_auth_hmacsha512_keygen() hmac512key \gset
select crypto_auth_hmacsha512('food', :'hmac512key'::bytea) hmac512 \gset

select throws_ok($$select crypto_auth_hmacsha512(NULL::bytea, 'bad')$$, '22000',
     'pgsodium_crypto_auth_hmacsha512: message cannot be NULL', 'hmac512 null data');
select throws_ok($$select crypto_auth_hmacsha512('bad', NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512: key cannot be NULL', 'hmac512 null key');

select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'hmac512key'::bytea), true, 'hmac512 verified');
select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'hmac512key'::bytea), false, 'hmac512 not verified');

select throws_ok($$select crypto_auth_hmacsha512_verify(NULL::bytea, 'bad', 'bad')$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify: hash cannot be NULL', 'hmac512_verify null hash');
select throws_ok($$select crypto_auth_hmacsha512_verify('bad', NULL::bytea, 'bad')$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify: message cannot be NULL', 'hmac512_verify null message');
select throws_ok($$select crypto_auth_hmacsha512_verify('bad', 'bad', NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify: key cannot be NULL', 'hmac512_verify null key');

select crypto_auth_hmacsha256_keygen() hmac256key \gset
select crypto_auth_hmacsha256('food', :'hmac256key'::bytea) hmac256 \gset

select throws_ok($$select crypto_auth_hmacsha256(NULL::bytea, 'bad')$$, '22000',
     'pgsodium_crypto_auth_hmacsha256: message cannot be NULL', 'hmac256 null data');
select throws_ok($$select crypto_auth_hmacsha256('bad', NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256: key cannot be NULL', 'hmac256 null key');

select is(crypto_auth_hmacsha256_verify(:'hmac256', 'food', :'hmac256key'::bytea), true, 'hmac256 verified');
select is(crypto_auth_hmacsha256_verify(:'hmac256', 'fo0d', :'hmac256key'::bytea), false, 'hmac256 not verified');

select throws_ok($$select crypto_auth_hmacsha256_verify(NULL::bytea, 'bad', 'bad')$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify: hash cannot be NULL', 'hmac256_verify null hash');
select throws_ok($$select crypto_auth_hmacsha256_verify('bad', NULL::bytea, 'bad')$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify: message cannot be NULL', 'hmac256_verify null message');
select throws_ok($$select crypto_auth_hmacsha256_verify('bad', 'bad', NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify: key cannot be NULL', 'hmac256_verify null key');

\if :serverkeys

select crypto_auth_hmacsha512('food', 42) hmac512 \gset

select throws_ok($$select crypto_auth_hmacsha512(NULL::bytea, 1)$$, '22000',
     'pgsodium_crypto_auth_hmacsha512_by_id: message cannot be NULL', 'hmac512 null data');
select throws_ok($$select crypto_auth_hmacsha512('bad', NULL::bigint)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_by_id: key id cannot be NULL', 'hmac512 null key id');
select throws_ok($$select crypto_auth_hmacsha512('bad', 1, NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_by_id: key context cannot be NULL', 'hmac512 null key  context');

select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', 42), true, 'hmac512 verified');
select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', 42), false, 'hmac512 not verified');

select throws_ok($$select crypto_auth_hmacsha512_verify(NULL::bytea, 'bad', 1)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify_by_id: hash cannot be NULL', 'hmac512_verify null hash');
select throws_ok($$select crypto_auth_hmacsha512_verify('bad', NULL::bytea, 1)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify_by_id: message cannot be NULL', 'hmac512_verify null message');
select throws_ok($$select crypto_auth_hmacsha512_verify('bad', 'bad', NULL::bigint)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify_by_id: key id cannot be NULL', 'hmac512_verify null key');
select throws_ok($$select crypto_auth_hmacsha512_verify('bad', 'bad', 1, NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha512_verify_by_id: key context cannot be NULL', 'hmac512_verify null key');

select crypto_auth_hmacsha256('food', 42) hmac256 \gset

select throws_ok($$select crypto_auth_hmacsha256(NULL::bytea, 1)$$, '22000',
     'pgsodium_crypto_auth_hmacsha256_by_id: message cannot be NULL', 'hmac256 null data');
select throws_ok($$select crypto_auth_hmacsha256('bad', NULL::bigint)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_by_id: key id cannot be NULL', 'hmac256 null key id');
select throws_ok($$select crypto_auth_hmacsha256('bad', 1, NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_by_id: key context cannot be NULL', 'hmac256 null key  context');

select is(crypto_auth_hmacsha256_verify(:'hmac256', 'food', 42), true, 'hmac256 verified');
select is(crypto_auth_hmacsha256_verify(:'hmac256', 'fo0d', 42), false, 'hmac256 not verified');

select throws_ok($$select crypto_auth_hmacsha256_verify(NULL::bytea, 'bad', 1)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify_by_id: hash cannot be NULL', 'hmac256_verify null hash');
select throws_ok($$select crypto_auth_hmacsha256_verify('bad', NULL::bytea, 1)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify_by_id: message cannot be NULL', 'hmac256_verify null message');
select throws_ok($$select crypto_auth_hmacsha256_verify('bad', 'bad', NULL::bigint)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify_by_id: key id cannot be NULL', 'hmac256_verify null key');
select throws_ok($$select crypto_auth_hmacsha256_verify('bad', 'bad', 1, NULL::bytea)$$, '22000',
    'pgsodium_crypto_auth_hmacsha256_verify_by_id: key context cannot be NULL', 'hmac256_verify null key');

select crypto_auth_hmacsha256_keygen() extkey256 \gset
select * from pgsodium.create_key('hmacsha256', raw_key:=:'extkey256') \gset extkey256_

select crypto_auth_hmacsha512_keygen() extkey512 \gset
select * from pgsodium.create_key('hmacsha512', raw_key:=:'extkey512') \gset extkey512_

select crypto_auth_hmacsha512('food', :'extkey512_id'::uuid) hmac512 \gset

select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'extkey512_id'::uuid), true, 'external hmac512 verified');
select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'extkey512_id'::uuid), false, 'external hmac512 not verified');

select crypto_auth_hmacsha256('food', :'extkey256_id'::uuid) hmac256 \gset

select is(crypto_auth_hmacsha256_verify(:'hmac256', 'food', :'extkey256_id'::uuid), true, 'external hmac256 verified');
select is(crypto_auth_hmacsha256_verify(:'hmac256', 'fo0d', :'extkey256_id'::uuid), false, 'external hmac256 not verified');

\endif
