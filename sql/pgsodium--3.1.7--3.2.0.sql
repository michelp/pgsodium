/*
 * change: replaced in 3.0.5 with "create_mask_view(oid, integer, boolean)".
 */
DROP FUNCTION IF EXISTS pgsodium.create_mask_view(oid, boolean);

/*
 * change: replaced in 3.0.5 by the "pgsodium.mask_columns" view.
 */
DROP FUNCTION IF EXISTS pgsodium.mask_columns(oid);
