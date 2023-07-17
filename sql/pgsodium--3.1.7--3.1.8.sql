
DROP FUNCTION pgsodium.quote_assoc;

CREATE FUNCTION pgsodium.quote_assoc(relnamespace regnamespace, relname name, assoc text, is_tgr boolean = false)
RETURNS text
AS $$
    WITH a AS (SELECT array_agg(CASE WHEN is_tgr THEN
                                    'new.' || quote_ident(trim(v))
                                ELSE quote_ident(trim(v)) END) as r
               FROM regexp_split_to_table(assoc, '\s*,\s*') as v)
    SELECT array_to_string(a.r, '::text || ') || '::text' FROM a;
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION pgsodium.quote_assoc2(relnamespace regnamespace, relname name, assoc text, is_tgr boolean = false)
RETURNS text
AS $$
DECLARE
    result text = '';
    colname text;
BEGIN
    FOR colname in (SELECT * FROM regexp_split_to_table(assoc, '\s*,\s*')) LOOP
        IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = relnamespace::text AND table_name = relname::text) THEN
            RAISE EXCEPTION 'Nonexistent associated column % for % %', colname, relnamespace, relname
              USING HINT = 'Please check your security label';
        END IF;
    END LOOP;
    RETURN result;

        -- WITH a AS (SELECT array_agg(CASE WHEN is_tgr THEN
        --                             'new.' || quote_ident(trim(v))
        --                         ELSE quote_ident(trim(v)) END) as r
        --        FROM regexp_split_to_table(assoc, '\s*,\s*') as v)
        -- SELECT array_to_string(a.r, '::text || ') || '::text' FROM a INTO result;
        -- RETURN result;
END;
$$ LANGUAGE plpgsql;

DROP VIEW pgsodium.mask_columns;
CREATE VIEW pgsodium.mask_columns AS SELECT
  a.attname,
  a.attrelid,
  m.relname,
  m.relnamespace,
  m.key_id,
  m.key_id_column,
  m.associated_columns,
  m.nonce_column,
  m.format_type
  FROM pg_attribute a
  LEFT JOIN  pgsodium.masking_rule m
  ON m.attrelid = a.attrelid
  AND m.attname = a.attname
  WHERE a.attnum > 0 -- exclude ctid, cmin, cmax
    AND NOT a.attisdropped
  ORDER BY a.attnum;

CREATE OR REPLACE FUNCTION pgsodium.decrypted_columns(relid OID)
RETURNS TEXT AS
$$
DECLARE
  m RECORD;
  expression TEXT;
  comma TEXT;
  padding text = '        ';
BEGIN
  expression := E'\n';
  comma := padding;
  FOR m IN SELECT * FROM pgsodium.mask_columns where attrelid = relid LOOP
    expression := expression || comma;
    IF m.key_id IS NULL AND m.key_id_column IS NULL THEN
      expression := expression || padding || quote_ident(m.attname);
    ELSE
      expression := expression || padding || quote_ident(m.attname) || E',\n';
      IF m.format_type = 'text' THEN
          expression := expression || format(
            $f$
            CASE WHEN %s IS NULL THEN NULL ELSE
                CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.convert_from(
                  pgsodium.crypto_aead_det_decrypt(
                    pg_catalog.decode(%s, 'base64'),
                    pg_catalog.convert_to((%s)::text, 'utf8'),
                    %s::uuid,
                    %s
                  ),
                    'utf8') END
                END AS %s$f$,
                quote_ident(m.attname),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(pgsodium.quote_assoc(m.relnamespace, m.relname, m.associated_columns), quote_literal('')),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                coalesce(quote_ident(m.nonce_column), 'NULL'),
                quote_ident('decrypted_' || m.attname)
          );
      ELSIF m.format_type = 'bytea' THEN
          expression := expression || format(
            $f$
            CASE WHEN %s IS NULL THEN NULL ELSE
                CASE WHEN %s IS NULL THEN NULL ELSE pgsodium.crypto_aead_det_decrypt(
                    %s::bytea,
                    pg_catalog.convert_to((%s)::text, 'utf8'),
                    %s::uuid,
                    %s
                  ) END
                END AS %s$f$,
                quote_ident(m.attname),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(pgsodium.quote_assoc(m.relnamespace, m.relname, m.associated_columns), quote_literal('')),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                coalesce(quote_ident(m.nonce_column), 'NULL'),
                'decrypted_' || quote_ident(m.attname)
          );
      END IF;
    END IF;
    comma := E',       \n';
  END LOOP;
  RETURN expression;
END
$$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path=''
;

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
			COALESCE(pgsodium.quote_assoc(m.relnamespace, m.relname, m.associated_columns, true), quote_literal('')),
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
			COALESCE(pgsodium.quote_assoc(m.relnamespace, m.relname, m.associated_columns, true), quote_literal('')),
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


CREATE OR REPLACE FUNCTION pgsodium.trg_mask_update()
RETURNS EVENT_TRIGGER AS
$$
DECLARE
  r record;
BEGIN
  IF (SELECT bool_or(in_extension) FROM pg_event_trigger_ddl_commands()) THEN
    RAISE NOTICE 'skipping pgsodium mask regeneration in extension';
	RETURN;
  END IF;

  FOR r IN
    SELECT e.*
    FROM pg_event_trigger_ddl_commands() e
    WHERE EXISTS (
      SELECT FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_seclabel s ON s.classoid = c.tableoid
                                   AND s.objoid = c.oid
      WHERE c.tableoid = e.classid
        AND e.objid = c.oid
        AND s.provider = 'pgsodium'
    )
  LOOP
    IF r.object_type in ('table', 'table column')
    THEN
      PERFORM pgsodium.update_mask(r.objid);
    END IF;
  END LOOP;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;
