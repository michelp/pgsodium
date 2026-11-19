-- A preloaded string GUC's default must survive PostmasterContext deletion.
-- Checking only for a crash misses stale pointers that still contain text.
\if :serverkeys

SELECT ok(
    (SELECT boot_val = (
        SELECT setting || '/extension/pgsodium_getkey'
        FROM pg_config() WHERE name = 'SHAREDIR'
    ) FROM pg_settings WHERE name = 'pgsodium.getkey_script'),
    'getkey_script default survives backend initialization'
);

SELECT is(
    (SELECT setting FROM pg_settings WHERE name = 'pgsodium.getkey_script'),
    current_setting('pgsodium.getkey_script'),
    'getkey_script setting matches the active default or configured override'
);

SELECT is(
    (SELECT reset_val FROM pg_settings WHERE name = 'pgsodium.getkey_script'),
    current_setting('pgsodium.getkey_script'),
    'getkey_script reset value matches the startup configuration'
);

\else
SELECT * FROM skip('getkey_script requires shared preloading', 3);
\endif
