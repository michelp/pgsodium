
CREATE OR REPLACE FUNCTION pgsodium.encrypted_column(relid OID, m record)
RETURNS TEXT AS
$$
DECLARE
    expression TEXT;
    comma TEXT;
BEGIN
  expression := '';
  comma := E'        ';
  expression := expression || comma;
  IF m.format_type = 'text' THEN
	  expression := expression || format(
		$f$%s = CASE WHEN %s IS NULL THEN NULL ELSE
			CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.encode(
			  pgsodium.crypto_aead_det_encrypt(
				pg_catalog.convert_to(%s, 'utf8'),
				pg_catalog.convert_to((%s)::text, 'utf8'),
				%s::uuid,
				%s
			  ),
				'base64') END END$f$,
			'new.' || quote_ident(m.attname),
			'new.' || quote_ident(m.attname),
			COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
			'new.' || quote_ident(m.attname),
			COALESCE(pgsodium.quote_assoc(m.associated_columns, true), quote_literal('')),
			COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
			COALESCE('new.' || quote_ident(m.nonce_column), 'NULL')
	  );
  ELSIF m.format_type = 'bytea' THEN
	  expression := expression || format(
		$f$%s = CASE WHEN %s IS NULL THEN NULL ELSE
			CASE WHEN %s IS NULL THEN NULL ELSE
					pgsodium.crypto_aead_det_encrypt(%s::bytea, pg_catalog.convert_to((%s)::text, 'utf8'),
			%s::uuid,
			%s
		  ) END END$f$,
			'new.' || quote_ident(m.attname),
			'new.' || quote_ident(m.attname),
			COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
			'new.' || quote_ident(m.attname),
			COALESCE(pgsodium.quote_assoc(m.associated_columns, true), quote_literal('')),
			COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
			COALESCE('new.' || quote_ident(m.nonce_column), 'NULL')
	  );
  END IF;
  comma := E';\n        ';
  RETURN expression;
END
$$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path=''
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
BEGIN
  SELECT * INTO STRICT rule FROM pgsodium.masking_rule WHERE attrelid = relid and attnum = subid ;

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
    pgsodium.decrypted_columns(relid),
    source_name,
    rule.view_name,
    view_owner
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

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

CREATE OR REPLACE FUNCTION pgsodium.update_masks(debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM pgsodium.update_mask(objoid, debug)
    FROM pg_catalog.pg_seclabel sl
    JOIN pg_catalog.pg_class cl ON (cl.oid = sl.objoid)
    WHERE label ilike 'ENCRYPT%'
       AND cl.relowner = session_user::regrole::oid
       AND provider = 'pgsodium'
	   AND objoid::regclass != 'pgsodium.key'::regclass
	;
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

DROP TRIGGER key_encrypt_secret_trigger ON pgsodium.key;
DROP FUNCTION pgsodium.key_encrypt_secret();
SELECT pgsodium.update_mask('pgsodium.key'::regclass::oid);
