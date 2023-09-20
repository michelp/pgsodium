CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false)
    RETURNS void AS
  $$
DECLARE
  m record;
  body text;
  source_name text;
  view_owner regrole = quote_ident(session_user);
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
    DROP VIEW IF EXISTS %1$s;
    CREATE VIEW %1$s %5$s AS SELECT %2$s
    FROM %3$s;
    ALTER VIEW %1$s OWNER TO %4$s;
    $c$,
    rule.view_name,
    pgsodium.decrypted_columns(relid),
    source_name,
    view_owner,
    CASE WHEN rule.security_invoker THEN 'WITH (security_invoker=true)' ELSE '' END
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
		DROP FUNCTION IF EXISTS %1$s."%2$s_encrypt_secret_%3$s"() CASCADE;

		CREATE OR REPLACE FUNCTION %1$s."%2$s_encrypt_secret_%3$s"()
		  RETURNS TRIGGER
		  LANGUAGE plpgsql
		  AS $t$
		BEGIN
		%4$s;
		RETURN new;
		END;
		$t$;

		ALTER FUNCTION  %1$s."%2$s_encrypt_secret_%3$s"() OWNER TO %5$s;

		DROP TRIGGER IF EXISTS "%2$s_encrypt_secret_trigger_%3$s" ON %6$s;

		CREATE TRIGGER "%2$s_encrypt_secret_trigger_%3$s"
		  BEFORE INSERT OR UPDATE OF "%3$s" ON %6$s
		  FOR EACH ROW
		  EXECUTE FUNCTION %1$s."%2$s_encrypt_secret_%3$s" ();
		  $c$,
		rule.relnamespace,
		rule.relname,
		m.attname,
		pgsodium.encrypted_column(relid, m),
		view_owner,
		source_name
	  );
	  if debug THEN
		RAISE NOTICE '%', body;
	  END IF;
	  EXECUTE body;
	END IF;
  END LOOP;

  raise notice 'about to masking role % %', source_name, rule.view_name;
  PERFORM pgsodium.mask_role(oid::regrole, source_name, rule.view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;

CREATE OR REPLACE FUNCTION pgsodium.update_masks(debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM pgsodium.update_mask(objoid, debug)
    FROM pg_catalog.pg_seclabel sl
    JOIN pg_catalog.pg_class cl ON (cl.oid = sl.objoid)
    WHERE label ilike 'ENCRYPT%'
       AND cl.relowner = quote_ident(session_user)::regrole::oid
       AND provider = 'pgsodium'
	   AND objoid::regclass != 'pgsodium.key'::regclass
	;
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

CREATE VIEW pgsodium.seclabel AS
    SELECT nspname, relname, attname, label
    FROM pg_seclabel sl,
         pg_class c,
         pg_attribute a,
         pg_namespace n
    WHERE sl.objoid = c.oid
    AND c.oid = a.attrelid
    AND a.attnum = sl.objsubid
    AND n.oid = c.relnamespace;
