DROP EVENT TRIGGER  pgsodium_trg_mask_update;

CREATE EVENT TRIGGER pgsodium_trg_mask_update
  ON ddl_command_end
  WHEN TAG IN (
    'SECURITY LABEL'
  )
  EXECUTE PROCEDURE @extschema@.trg_mask_update()
;

ALTER EXTENSION pgsodium DROP FUNCTION @extschema@.key_encrypt_secret();

CREATE FUNCTION @extschema@.update_mask(target oid, debug boolean = false)
RETURNS void AS
  $$
BEGIN
  ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE;
  PERFORM @extschema@.create_mask_view(objoid, objsubid, debug)
    FROM pg_catalog.pg_seclabel
    WHERE objoid = target
        AND label ILIKE 'ENCRYPT%'
        AND provider = 'pgsodium';
  ALTER EVENT TRIGGER pgsodium_trg_mask_update ENABLE;
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path=''
;

CREATE OR REPLACE FUNCTION @extschema@.update_masks(debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM @extschema@.update_mask(objoid, debug)
    FROM pg_catalog.pg_seclabel
    WHERE label ilike 'ENCRYPT%'
       AND provider = 'pgsodium';
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

CREATE OR REPLACE FUNCTION @extschema@.create_mask_view(relid oid, subid integer, debug boolean = false) RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  rule @extschema@.masking_rule;
BEGIN
  SELECT * INTO STRICT rule FROM @extschema@.masking_rule WHERE attrelid = relid and attnum = subid ;

  source_name := relid::regclass;

  body = format(
    $c$
    DROP VIEW IF EXISTS %s;
    CREATE VIEW %s AS SELECT %s
    FROM %s;
    $c$,
    rule.view_name,
    rule.view_name,
    @extschema@.decrypted_columns(relid),
    source_name
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
