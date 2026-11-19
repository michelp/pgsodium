\if :serverkeys

-- The boot value of pgsodium.getkey_script must survive backend startup.
--
-- DefineCustomStringVariable() stores the bootValue pointer as-is without
-- copying the string, and pg_settings dereferences it lazily on every read.
-- The buffer therefore has to outlive PostmasterContext, which every backend
-- frees during InitPostgres().  When it does not, boot_val reads freed memory
-- and returns garbage that varies per backend and may not even be valid in the
-- database encoding.  See _PG_init() in src/pgsodium.c.
--
-- Note this holds regardless of whether pgsodium.getkey_script has been
-- overridden in the config: boot_val is always the built-in default.
select is(
    (select boot_val from pg_settings where name = 'pgsodium.getkey_script'),
    (select setting from pg_config where name = 'SHAREDIR') || '/extension/pgsodium_getkey',
    'pgsodium.getkey_script boot_val is the default getkey script path');

\endif
