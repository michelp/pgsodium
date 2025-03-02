CREATE OR REPLACE VIEW pgsodium.masking_rule AS
  WITH const AS (
    SELECT
      'encrypt +with +key +id +([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
        AS pattern_key_id,
      'encrypt +with +key +column +([\w\"\-$]+)'
        AS pattern_key_id_column,
      '(?<=associated) +\(([\w\"\-$, ]+)\)'
        AS pattern_associated_columns,
      '(?<=nonce) +([\w\"\-$]+)'
        AS pattern_nonce_column,
      '(?<=decrypt with view) +([\w\"\-$]+\.[\w\"\-$]+)'
        AS pattern_view_name,
      '(?<=security invoker)'
        AS pattern_security_invoker
  ),
  rules_from_seclabels AS (
    SELECT
      sl.objoid AS attrelid,
      sl.objsubid  AS attnum,
      c.relnamespace::regnamespace,
      c.relname,
      a.attname,
      pg_catalog.format_type(a.atttypid, a.atttypmod),
      sl.label AS col_description,
      (regexp_match(sl.label, k.pattern_key_id_column, 'i'))[1] AS key_id_column,
      (regexp_match(sl.label, k.pattern_key_id, 'i'))[1] AS key_id,
      (regexp_match(sl.label, k.pattern_associated_columns, 'i'))[1] AS associated_columns,
      (regexp_match(sl.label, k.pattern_nonce_column, 'i'))[1] AS nonce_column,
      coalesce((regexp_match(sl2.label, k.pattern_view_name, 'i'))[1],
               c.relnamespace::regnamespace || '.' || quote_ident('decrypted_' || c.relname)) AS view_name,
      100 AS priority,
      (regexp_match(sl.label, k.pattern_security_invoker, 'i'))[1] IS NOT NULL AS security_invoker
      FROM const k,
           pg_catalog.pg_seclabel sl
           JOIN pg_catalog.pg_class c ON sl.classoid = c.tableoid AND sl.objoid = c.oid
           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND sl.objsubid = a.attnum
           LEFT JOIN pg_catalog.pg_seclabel sl2 ON sl2.objoid = c.oid AND sl2.objsubid = 0
     WHERE a.attnum > 0
       AND c.relnamespace::regnamespace != 'pg_catalog'::regnamespace
       AND NOT a.attisdropped
       AND sl.label ilike 'ENCRYPT%'
       AND sl.provider = 'pgsodium'
  )
  SELECT
    DISTINCT ON (attrelid, attnum) *
    FROM rules_from_seclabels
   ORDER BY attrelid, attnum, priority DESC;

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
