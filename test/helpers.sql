BEGIN;
SELECT plan(1);

select sodium_bin2base64('bob is your uncle') basebob \gset
select is(sodium_base642bin(:'basebob'), 'bob is your uncle'::bytea, 'base64');

SELECT * FROM finish();
ROLLBACK;
