
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

  -- view_name may be a schema-qualified name (default 'schema.decrypted_<rel>')
  -- or a user-supplied 'DECRYPT WITH VIEW' name from a SECURITY LABEL, which is
  -- untrusted.  Casting to regclass both validates that it resolves to a real
  -- relation (rejecting injection payloads, which cannot cast) and renders it
  -- back as a safely-quoted, schema-qualified identifier.
  EXECUTE format(
    'GRANT ALL ON %s TO %s',
    view_name::regclass,
    masked_role);
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog, pg_temp'
;

