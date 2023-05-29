
select sodium_bin2base64('bob is your uncle') basebob \gset
select throws_ok('select sodium_bin2base64(NULL)',
    '22000', 'pgsodium_sodium_bin2base64: bin cannot be NULL', 'sodium_bin2base64 null input');

select is(sodium_base642bin(:'basebob'), 'bob is your uncle'::bytea, 'base64');

select throws_ok('select sodium_base642bin(NULL)',
    '22000', 'pgsodium_sodium_base642bin: base64 cannot be NULL', 'sodium_base642bin null input');

