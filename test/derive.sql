\if :serverkeys
BEGIN;
SELECT plan(4);

select is(derive_key(1), derive_key(1), 'derived key are equal by id');
select isnt(derive_key(1), derive_key(2), 'disequal derived key');
select is(length(derive_key(2, 64)), 64, 'key len is 64 bytes');
select isnt(derive_key(2, 32, 'foozball'), derive_key(2, 32), 'disequal context');
SELECT * FROM finish();

SELECT * FROM finish();
ROLLBACK;
\endif
