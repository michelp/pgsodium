\if :serverkeys

select is(derive_key(1), derive_key(1), 'derived key are equal by id');
select throws_ok($$select derive_key(NULL)$$, '22000', 'pgsodium_derive: key id cannot be NULL', 'null key id');
select throws_ok($$select derive_key(1, NULL)$$, '22000', 'pgsodium_derive: key size cannot be NULL', 'null key size');
select throws_ok($$select derive_key(1, 64, NULL)$$, '22000', 'pgsodium_derive: key context cannot be NULL', 'null key context');
select isnt(derive_key(1), derive_key(2), 'disequal derived key');
select is(length(derive_key(2, 64)), 64, 'key len is 64 bytes');
select isnt(derive_key(2, 32, 'foozball'), derive_key(2, 32), 'disequal context');

\endif
