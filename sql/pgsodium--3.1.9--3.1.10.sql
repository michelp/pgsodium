
CREATE OR REPLACE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS
  $$
BEGIN
  EXECUTE format(
    'GRANT SELECT ON pgsodium.key TO %s',
    masked_role);

  EXECUTE format(
    'GRANT pgsodium_keyiduser, pgsodium_keyholder TO %s',
    masked_role);

  EXECUTE format(
    'GRANT ALL ON %I TO %s',
    view_name,
    masked_role);
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog, pg_temp'
;

