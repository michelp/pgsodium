
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks GRANT ALL ON TABLES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks GRANT ALL ON SEQUENCES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks GRANT ALL ON FUNCTIONS TO pgsodium_keyiduser;

-- pgsodium_keyiduser can use all tables and sequences (functions are granted individually)
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON TABLES FROM pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON SEQUENCES FROM pgsodium_keyiduser;

ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON TABLES TO pgsodium_keyholder;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON SEQUENCES TO pgsodium_keyholder;

REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM pgsodium_keyiduser;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM pgsodium_keyiduser;

GRANT ALL ON ALL TABLES IN SCHEMA pgsodium TO pgsodium_keyholder;
GRANT ALL ON ALL SEQUENCES IN SCHEMA pgsodium TO pgsodium_keyholder;

GRANT SELECT ON pgsodium.valid_key TO pgsodium_keyiduser;

ALTER TYPE pgsodium.key_type ADD VALUE 'hmacsha512';
ALTER TYPE pgsodium.key_type ADD VALUE 'hmacsha256';

ALTER TABLE pgsodium.key ADD COLUMN raw_key bytea;
ALTER TABLE pgsodium.key ADD COLUMN raw_key_nonce bytea;
ALTER TABLE pgsodium.key ADD COLUMN parent_key uuid REFERENCES pgsodium.key(id);
ALTER TABLE pgsodium.key RENAME comment TO name;
ALTER TABLE pgsodium.key ALTER COLUMN key_id DROP NOT NULL;
ALTER TABLE pgsodium.key ALTER COLUMN key_context DROP NOT NULL;
ALTER TABLE pgsodium.key ADD CONSTRAINT pgsodium_key_unique_name UNIQUE (name);
ALTER TABLE pgsodium.key ADD CONSTRAINT pgsodium_raw CHECK (
  CASE WHEN
        raw_key IS NOT NULL
    THEN key_id IS NULL     AND key_context IS NULL     AND parent_key IS NOT NULL
    ELSE key_id IS NOT NULL AND key_context IS NOT NULL AND parent_key IS NULL
  END);

DROP FUNCTION pgsodium.create_key(text, pgsodium.key_type, bigint, bytea, timestamp, jsonb);

CREATE FUNCTION @extschema@.create_key (
  name text = NULL,
  key_type @extschema@.key_type = 'aead-det',
  raw_key bytea = NULL,
  raw_key_nonce bytea = NULL,
  key_context bytea = 'pgsodium',
  parent_key uuid = NULL,
  expires timestamp = NULL,
  user_data jsonb = NULL
) RETURNS @extschema@.key
AS $$
DECLARE
  new_key pgsodium.key;
BEGIN
    INSERT INTO @extschema@.key (key_id, key_context, key_type, raw_key,
	raw_key_nonce, parent_key, expires, name, user_data)
        VALUES (
            CASE WHEN raw_key IS NULL THEN
                NEXTVAL('@extschema@.key_key_id_seq'::REGCLASS)
            ELSE NULL END,
            CASE WHEN raw_key IS NULL THEN
                key_context
            ELSE NULL END,
            key_type,
            raw_key,
            CASE WHEN raw_key IS NOT NULL THEN
                COALESCE(raw_key_nonce, pgsodium.crypto_aead_det_noncegen ())
            ELSE NULL END,
            CASE WHEN parent_key IS NULL and raw_key IS NOT NULL THEN
                (pgsodium.create_key()).id
            ELSE parent_key END,
            expires,
            name,
            user_data)
      RETURNING * into new_key;
  RETURN new_key;
END;
$$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.create_key OWNER TO pgsodium_keyholder;
  GRANT EXECUTE ON FUNCTION pgsodium.create_key TO pgsodium_keyiduser;

ALTER VIEW pgsodium.valid_key RENAME COLUMN comment TO name;
CREATE OR REPLACE VIEW pgsodium.valid_key AS
  SELECT * FROM pgsodium.key
   WHERE  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires < now() END;

-- HMAC external key support

CREATE OR REPLACE FUNCTION pgsodium.crypto_auth_hmacsha256(message bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'hmacsha256';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth_hmacsha256(message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth_hmacsha256(message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, uuid) OWNER TO pgsodium_keyholder;

CREATE OR REPLACE FUNCTION pgsodium.crypto_auth_hmacsha256_verify(signature bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'hmacsha256';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth_hmacsha256_verify(signature, message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth_hmacsha256_verify(signature, message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) OWNER TO pgsodium_keyholder;

CREATE OR REPLACE FUNCTION pgsodium.crypto_auth_hmacsha512(message bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'hmacsha512';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth_hmacsha512(message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth_hmacsha512(message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, uuid) OWNER TO pgsodium_keyholder;

CREATE OR REPLACE FUNCTION pgsodium.crypto_auth_hmacsha512_verify(signature bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'hmacsha512';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth_hmacsha512_verify(signature, message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth_hmacsha512_verify(signature, message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) OWNER TO pgsodium_keyholder;

-- bytea and extended associated data support for encrypted columns

DROP VIEW pgsodium.masking_rule CASCADE;
CREATE OR REPLACE VIEW pgsodium.masking_rule AS
  WITH const AS (
    SELECT
      'encrypt +with +key +id +([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
        AS pattern_key_id,
      'encrypt +with +key +column +(\w+)'
        AS pattern_key_id_column,
      '(?<=associated) +(\w+)'
        AS pattern_associated_column,
      '(?<=nonce) +(\w+)'
        AS pattern_nonce_column,
      '(?<=decrypt with view) +(\w+\.\w+)'
        AS pattern_view_name
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
      (regexp_match(sl.label, k.pattern_associated_column, 'i'))[1] AS associated_column,
      (regexp_match(sl.label, k.pattern_nonce_column, 'i'))[1] AS nonce_column,
      coalesce((regexp_match(sl2.label, k.pattern_view_name, 'i'))[1],
               c.relnamespace::regnamespace || '.' || quote_ident('decrypted_' || c.relname)) AS view_name,
      100 AS priority
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

CREATE VIEW pgsodium.mask_columns AS SELECT
  a.attname,
  a.attrelid,
  m.key_id,
  m.key_id_column,
  m.associated_column,
  m.nonce_column,
  m.format_type
  FROM pg_attribute a
  LEFT JOIN  @extschema@.masking_rule m
  ON m.attrelid = a.attrelid
  AND m.attname = a.attname
  WHERE  a.attnum > 0 -- exclude ctid, cmin, cmax
  AND    NOT a.attisdropped
  ORDER BY a.attnum;

CREATE OR REPLACE FUNCTION pgsodium.encrypted_columns(
  relid OID
)
RETURNS TEXT AS
$$
DECLARE
    m RECORD;
    expression TEXT;
    comma TEXT;
BEGIN
  expression := '';
  comma := E'        ';
  FOR m IN SELECT * FROM @extschema@.mask_columns where attrelid = relid LOOP
    IF m.key_id IS NULL AND m.key_id_column is NULL THEN
      CONTINUE;
    ELSE
      expression := expression || comma;
      IF m.format_type = 'text' THEN
          expression := expression || format(
            $f$%s = CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.encode(
              @extschema@.crypto_aead_det_encrypt(
                pg_catalog.convert_to(%s, 'utf8'),
                pg_catalog.convert_to(%s::text, 'utf8'),
                %s::uuid,
                %s
              ),
                'base64') END$f$,
                'new.' || quote_ident(m.attname),
                COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
                'new.' || quote_ident(m.attname),
                COALESCE('new.' || quote_ident(m.associated_column), quote_literal('')),
                COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
                COALESCE('new.' || quote_ident(m.nonce_column), 'NULL')
          );
      ELSIF m.format_type = 'bytea' THEN
          expression := expression || format(
            $f$%s = CASE WHEN %s IS NULL THEN NULL ELSE @extschema@.crypto_aead_det_encrypt(%s::bytea, pg_catalog.convert_to(%s::text, 'utf8'),
                %s::uuid,
                %s
              ) END
              $f$,
                'new.' || quote_ident(m.attname),
                COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
                'new.' || quote_ident(m.attname),
                COALESCE('new.' || quote_ident(m.associated_column), quote_literal('')),
                COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
                COALESCE('new.' || quote_ident(m.nonce_column), 'NULL')
          );
      END IF;
    END IF;
    comma := E';\n        ';
  END LOOP;
  RETURN expression;
END
$$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path=''
  ;

CREATE OR REPLACE FUNCTION pgsodium.decrypted_columns(
  relid OID
)
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
  FOR m IN SELECT * FROM @extschema@.mask_columns where attrelid = relid LOOP
    expression := expression || comma;
    IF m.key_id IS NULL AND m.key_id_column IS NULL THEN
      expression := expression || padding || quote_ident(m.attname);
    ELSE
      expression := expression || padding || quote_ident(m.attname) || E',\n';
      IF m.format_type = 'text' THEN
          expression := expression || format(
            $f$
            CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.convert_from(
              @extschema@.crypto_aead_det_decrypt(
                pg_catalog.decode(%s, 'base64'),
                pg_catalog.convert_to(%s::text, 'utf8'),
                %s::uuid,
                %s
              ),
                'utf8') END AS %s$f$,
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(quote_ident(m.associated_column), quote_literal('')),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                coalesce(quote_ident(m.nonce_column), 'NULL'),
                'decrypted_' || quote_ident(m.attname)
          );
      ELSIF m.format_type = 'bytea' THEN
          expression := expression || format(
            $f$
            CASE WHEN %s IS NULL THEN NULL ELSE @extschema@.crypto_aead_det_decrypt(
                %s::bytea,
                pg_catalog.convert_to(%s::text, 'utf8'),
                %s::uuid,
                %s
              ) END AS %s$f$,
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(quote_ident(m.associated_column), quote_literal('')),
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

CREATE OR REPLACE FUNCTION @extschema@.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS
  $$
BEGIN
  EXECUTE format('GRANT pgsodium_keyiduser TO %s', masked_role);
  EXECUTE format('GRANT ALL ON %s TO %s', view_name, masked_role);
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path='pg_catalog'
;

CREATE OR REPLACE FUNCTION @extschema@.create_mask_view(relid oid, subid integer, debug boolean = false) RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  rule @extschema@.masking_rule;
BEGIN
  SELECT * INTO STRICT rule FROM pgsodium.masking_rule WHERE attrelid = relid and attnum = subid ;

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

CREATE OR REPLACE FUNCTION pgsodium.update_masks(debug boolean = false)
RETURNS void AS
  $$
BEGIN
  PERFORM pgsodium.create_mask_view(objoid, objsubid, debug)
    FROM (SELECT sl.objoid, sl.objsubid
            FROM pg_catalog.pg_seclabel sl, pg_catalog.pg_class cl, pg_catalog.pg_namespace ns
           WHERE sl.classoid = cl.oid
             AND cl.relnamespace = ns.oid
             AND cl.relkind IN ('r', 'p', 'f') -- table, partition, or foreign
             AND sl.label ilike 'ENCRYPT%'
             AND sl.provider = 'pgsodium') c;
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path=''
;

-- -- pgsodium_keymaker

-- DO $$
-- DECLARE
-- 	func text;
-- BEGIN
-- 	FOREACH func IN ARRAY
-- 	ARRAY[
--     ]
-- 	LOOP
-- 		EXECUTE format($i$
-- 			REVOKE ALL ON FUNCTION %s FROM PUBLIC;
-- 			GRANT EXECUTE ON FUNCTION %s TO pgsodium_keymaker;
-- 		$i$, func, func);
-- 	END LOOP;
-- END
-- $$;

-- -- pgsodium_keyholder

-- DO $$
-- DECLARE
-- 	func text;
-- BEGIN
-- 	FOREACH func IN ARRAY
-- 	ARRAY[
-- 	]
-- 	LOOP
-- 		EXECUTE format($i$
-- 			REVOKE ALL ON FUNCTION %s FROM PUBLIC;
-- 			GRANT EXECUTE ON FUNCTION %s TO pgsodium_keyholder;
-- 		$i$, func, func);
-- 	END LOOP;
-- END
-- $$;

-- -- pgsodium_keyiduser

DO $$
DECLARE
	func text;
BEGIN
	FOREACH func IN ARRAY
	  ARRAY[
        'pgsodium.crypto_auth_hmacsha256(bytea, bigint, bytea)',
        'pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea)',
        'pgsodium.crypto_auth_hmacsha512(bytea, bigint, bytea)',
        'pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea)',
        'pgsodium.crypto_auth_hmacsha256(bytea, uuid)',
        'pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid)',
        'pgsodium.crypto_auth_hmacsha512(bytea, uuid)',
        'pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid)'
	]
	LOOP
		EXECUTE format($i$
			REVOKE ALL ON FUNCTION %s FROM PUBLIC;
			GRANT EXECUTE ON FUNCTION %s TO pgsodium_keyiduser;
		$i$, func, func);
	END LOOP;
END
$$;

SECURITY LABEL FOR pgsodium ON COLUMN pgsodium.key.raw_key
                 IS 'ENCRYPT WITH KEY COLUMN parent_key ASSOCIATED id NONCE raw_key_nonce';

ALTER EXTENSION pgsodium DROP VIEW pgsodium.decrypted_key;  -- so the view can be recreated

DELETE FROM pgsodium.key where status = 'default';
