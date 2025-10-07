

CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false)
    RETURNS void AS
  $$
DECLARE
  m record;
  body text;
  source_name text;
  view_owner regrole = session_user;
  rule pgsodium.masking_rule;
  privs aclitem[];
  priv record;
BEGIN
  SELECT DISTINCT * INTO STRICT rule FROM pgsodium.masking_rule WHERE attrelid = relid AND attnum = subid;
	
  source_name := relid::regclass::text;

  BEGIN
    SELECT relacl INTO STRICT privs FROM pg_catalog.pg_class WHERE oid = rule.view_name::regclass::oid;
  EXCEPTION
	WHEN undefined_table THEN
      SELECT relacl INTO STRICT privs FROM pg_catalog.pg_class WHERE oid = relid;
  END;

  body = format(
    $c$
    DROP VIEW IF EXISTS %s;
    CREATE VIEW %s AS SELECT %s
    FROM %s;
    ALTER VIEW %s OWNER TO %s;
    $c$,
    rule.view_name,
    rule.view_name,
    pgsodium.decrypted_columns(relid),
    source_name,
    rule.view_name,
    view_owner
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  FOR priv IN SELECT * FROM pg_catalog.aclexplode(privs) LOOP
	body = format(
	  $c$
	  GRANT %s ON %s TO %s;
	  $c$,
	  priv.privilege_type,
	  rule.view_name,
	  priv.grantee::regrole::text
	);
	IF debug THEN
	  RAISE NOTICE '%', body;
	END IF;
	EXECUTE body;
  END LOOP;
	
  FOR m IN SELECT * FROM pgsodium.mask_columns where attrelid = relid LOOP
	IF m.key_id IS NULL AND m.key_id_column is NULL THEN
	  CONTINUE;
	ELSE
	  body = format(
		$c$
		DROP FUNCTION IF EXISTS %s."%s_encrypt_secret_%s"() CASCADE;

		CREATE OR REPLACE FUNCTION %s."%s_encrypt_secret_%s"()
		  RETURNS TRIGGER
		  LANGUAGE plpgsql
		  AS $t$
		BEGIN
		%s;
		RETURN new;
		END;
		$t$;

		ALTER FUNCTION  %s."%s_encrypt_secret_%s"() OWNER TO %s;

		DROP TRIGGER IF EXISTS "%s_encrypt_secret_trigger_%s" ON %s;

		CREATE TRIGGER "%s_encrypt_secret_trigger_%s"
		  BEFORE INSERT OR UPDATE OF "%s" ON %s
		  FOR EACH ROW
		  EXECUTE FUNCTION %s."%s_encrypt_secret_%s" ();
		  $c$,
		rule.relnamespace,
		rule.relname,
		m.attname,
		rule.relnamespace,
		rule.relname,
		m.attname,
		pgsodium.encrypted_column(relid, m),
		rule.relnamespace,
		rule.relname,
		m.attname,
		view_owner,
		rule.relname,
		m.attname,
		source_name,
		rule.relname,
		m.attname,
		m.attname,
		source_name,
		rule.relnamespace,
		rule.relname,
		m.attname
	  );
	  if debug THEN
		RAISE NOTICE '%', body;
	  END IF;
	  EXECUTE body;
	END IF;
  END LOOP;

  PERFORM pgsodium.mask_role(oid::regrole, source_name, rule.view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;
