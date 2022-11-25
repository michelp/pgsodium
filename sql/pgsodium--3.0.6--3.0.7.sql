
-- This is for bw compat with old dumps that don't go through the UPDATE TO process
ALTER TABLE @extschema@.key ADD COLUMN comment text;

CREATE FUNCTION @extschema@.get_key_by_id(uuid) RETURNS @extschema@.valid_key
AS $$
    SELECT * from @extschema@.valid_key WHERE id = $1;
$$
SECURITY DEFINER
LANGUAGE sql
SET search_path = '';


CREATE FUNCTION @extschema@.get_key_by_name(text) RETURNS @extschema@.valid_key
AS $$
    SELECT * from @extschema@.valid_key WHERE name = $1;
$$
SECURITY DEFINER
LANGUAGE sql
SET search_path = '';

CREATE FUNCTION @extschema@.get_named_keys(filter text='%') RETURNS SETOF @extschema@.valid_key
AS $$
    SELECT * from @extschema@.valid_key vk WHERE vk.name ILIKE filter;
$$
SECURITY DEFINER
LANGUAGE sql
SET search_path = '';


DROP FUNCTION @extschema@.create_mask_view(oid, integer, boolean);
CREATE FUNCTION @extschema@.create_mask_view(relid oid, subid integer, debug boolean = false)
    RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  view_owner text = session_user;
  rule @extschema@.masking_rule;
BEGIN
  SELECT * INTO STRICT rule FROM @extschema@.masking_rule WHERE attrelid = relid and attnum = subid ;

  source_name := relid::regclass;

  body = format(
    $c$
    DROP VIEW IF EXISTS %s;
    CREATE VIEW %s AS SELECT %s
    FROM %s;
    ALTER VIEW %s OWNER TO %s;
    $c$,
    rule.view_name,
    rule.view_name,
    @extschema@.decrypted_columns(relid),
    source_name,
    rule.view_name,
    view_owner
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  body = format(
    $c$
    DROP FUNCTION IF EXISTS %s.%s_encrypt_secret() CASCADE;

    CREATE OR REPLACE FUNCTION %s.%s_encrypt_secret()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      AS $t$
    BEGIN
    %s;
    RETURN new;
    END;
    $t$;

    ALTER FUNCTION  %s.%s_encrypt_secret() OWNER TO %s;

    DROP TRIGGER IF EXISTS %s_encrypt_secret_trigger ON %s.%s;

    CREATE TRIGGER %s_encrypt_secret_trigger
      BEFORE INSERT ON %s
      FOR EACH ROW
      EXECUTE FUNCTION %s.%s_encrypt_secret ();
      $c$,
    rule.relnamespace,
    rule.relname,
    rule.relnamespace,
    rule.relname,
    @extschema@.encrypted_columns(relid),
    rule.relnamespace,
    rule.relname,
    view_owner,
    rule.relname,
    rule.relnamespace,
    rule.relname,
    rule.relname,
    source_name,
    rule.relnamespace,
    rule.relname
  );
  if debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  PERFORM @extschema@.mask_role(oid::regrole, source_name, rule.view_name)
  FROM pg_roles WHERE @extschema@.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;

CREATE FUNCTION @extschema@.enable_security_label_trigger() RETURNS void AS
  $$
    ALTER EVENT TRIGGER pgsodium_trg_mask_update ENABLE;
  $$
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path=''
;

CREATE FUNCTION @extschema@.disable_security_label_trigger() RETURNS void AS
  $$
    ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE;
  $$
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path=''
;

DROP FUNCTION @extschema@.update_mask(oid, boolean);
CREATE FUNCTION @extschema@.update_mask(target oid, debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM @extschema@.disable_security_label_trigger();
  PERFORM @extschema@.create_mask_view(objoid, objsubid, debug)
    FROM pg_catalog.pg_seclabel sl
    WHERE sl.objoid = target
      AND sl.label ILIKE 'ENCRYPT%'
      AND sl.provider = 'pgsodium';
  PERFORM @extschema@.enable_security_label_trigger();
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path=''
;

DROP FUNCTION @extschema@.update_masks(boolean);
CREATE FUNCTION @extschema@.update_masks(debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM @extschema@.update_mask(objoid, debug)
    FROM pg_catalog.pg_seclabel sl
    JOIN pg_catalog.pg_class cl ON (cl.oid = sl.objoid)
    WHERE label ilike 'ENCRYPT%'
       AND cl.relowner = session_user::regrole::oid
       AND provider = 'pgsodium';
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

CREATE OR REPLACE FUNCTION @extschema@.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS
$$
DECLARE
  key @extschema@.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM @extschema@.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-det';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN @extschema@.crypto_aead_det_encrypt(message, additional, key.decrypted_raw_key, nonce);
  END IF;
  RETURN @extschema@.crypto_aead_det_encrypt(message, additional, key.key_id, key.key_context, nonce);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path=''
  ;
    
CREATE OR REPLACE FUNCTION @extschema@.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS
  $$
  DECLARE
  mask_schema REGNAMESPACE = '@extschema@_masks';
  source_schema REGNAMESPACE = (regexp_split_to_array(source_name, '\.'))[1];
BEGIN
  EXECUTE format(
    'GRANT SELECT ON @extschema@.key TO %s',
    masked_role);

  EXECUTE format(
    'GRANT pgsodium_keyiduser TO %s',
    masked_role);

  EXECUTE format(
    'GRANT ALL ON %s TO %s',
    view_name,
    masked_role);
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog'
;

