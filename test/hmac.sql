
BEGIN;
SELECT plan(4);

select crypto_auth_hmacsha512_keygen() hmac512key \gset
select crypto_auth_hmacsha512('food', :'hmac512key') hmac512 \gset

select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'hmac512key'), true, 'hmac512 verified');
select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'hmac512key'), false, 'hmac512 not verified');

select crypto_auth_hmacsha256_keygen() hmac256key \gset
select crypto_auth_hmacsha256('food', :'hmac256key') hmac256 \gset

select is(crypto_auth_hmacsha256_verify(:'hmac256', 'food', :'hmac256key'), true, 'hmac256 verified');
select is(crypto_auth_hmacsha256_verify(:'hmac256', 'fo0d', :'hmac256key'), false, 'hmac256 not verified');

SELECT * FROM finish();
ROLLBACK;
