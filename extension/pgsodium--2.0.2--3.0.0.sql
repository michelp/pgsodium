-- All roles cannot execute functions in pgsodium
REVOKE ALL ON SCHEMA pgsodium FROM PUBLIC;
-- But they can see the objects in pgsodium
GRANT USAGE ON SCHEMA pgsodium TO PUBLIC;

-- By default, public can't use any table, functions, or sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- pgsodium_keyiduser can use all tables and sequences (functions are granted individually)
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON TABLES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON SEQUENCES TO pgsodium_keyiduser;

-- Create a schema to hold the masking views
CREATE SCHEMA pgsodium_masks;
-- Revoke all from public on that schema
REVOKE ALL ON SCHEMA pgsodium_masks FROM PUBLIC;

-- By default public can't use any tables, functions, or sequences in the mask schema
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- pgsodium_keyiduser can see objects in the schema.
GRANT USAGE ON SCHEMA pgsodium_masks TO pgsodium_keyiduser;

-- Misc functions

CREATE OR REPLACE FUNCTION pgsodium.version()
  RETURNS text
  AS $$ SELECT extversion FROM pg_extension WHERE extname = 'pgsodium' $$
  LANGUAGE sql;

-- Internal Key Management

CREATE TYPE pgsodium.key_status AS ENUM (
  'default',
  'valid',
  'invalid',
  'expired'
);

CREATE TYPE pgsodium.key_type AS ENUM (
  'aead-ietf',
  'aead-det'
);

CREATE TABLE pgsodium.key (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status pgsodium.key_status DEFAULT 'valid',
  created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires timestamp,
  key_type pgsodium.key_type,
  key_id bigserial NOT NULL,
  key_context bytea NOT NULL DEFAULT 'pgsodium' CHECK (length(key_context) = 8),
  comment text,
  user_data jsonb
);

SELECT pg_catalog.pg_extension_config_dump('pgsodium.key', '');

GRANT SELECT ON pgsodium.key TO pgsodium_keyiduser;
GRANT INSERT, UPDATE, DELETE ON pgsodium.key TO pgsodium_keymaker;

CREATE INDEX ON pgsodium.key (status)
  WHERE (status IN ('valid', 'default'));

CREATE UNIQUE INDEX ON pgsodium.key (status)
  WHERE (status = 'default');

CREATE UNIQUE INDEX ON pgsodium.key (key_id, key_context, key_type);

COMMENT ON TABLE pgsodium.key IS
  'This table holds metadata for derived keys given a key_id '
  'and key_context. The raw key is never stored.';

CREATE VIEW pgsodium.valid_key AS
  SELECT
    *
    FROM
      pgsodium.key
   WHERE
  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires < now() END;

CREATE FUNCTION pgsodium.create_key(
  comment text = null,
  key_type pgsodium.key_type = 'aead-det',
  key_id bigint = null,
  key_context bytea = 'pgsodium',
  expires timestamp = null,
  user_data jsonb = null) RETURNS pgsodium.key
        AS $$
        INSERT INTO pgsodium.key (key_id, key_context, key_type, expires, comment, user_data)
          VALUES (case when key_id is null then nextval('pgsodium.key_key_id_seq'::regclass) else key_id
                  end,
                  key_context,
                  key_type,
                  expires,
                  comment,
                  user_data) RETURNING *;
        $$ LANGUAGE sql;

-- Deterministic AEAD functions by key uuid

CREATE TYPE pgsodium._key_id_context AS (
  key_id bigint,
  key_context bytea
);

CREATE FUNCTION pgsodium.crypto_aead_det_noncegen()
RETURNS bytea
AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_noncegen'
LANGUAGE C VOLATILE;

GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_noncegen() TO pgsodium_keyiduser;

CREATE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT IMMUTABLE
  SET search_path=''
  ;

GRANT EXECUTE ON FUNCTION
  pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT IMMUTABLE
  SET search_path='';

GRANT EXECUTE ON FUNCTION
  crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

--- AEAD det with nonce

CREATE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS
$$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key_id.key_id, key_id.key_context, nonce);
END;
  $$
  LANGUAGE plpgsql
  STRICT IMMUTABLE
  SET search_path=''
  ;

GRANT EXECUTE ON FUNCTION
  pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  TO pgsodium_keyiduser;

CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS
  $$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key_id.key_id, key_id.key_context, nonce);
END;
  $$
  LANGUAGE plpgsql
  STRICT IMMUTABLE
  SET search_path='';

GRANT EXECUTE ON FUNCTION
  crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  TO pgsodium_keyiduser;

-- IETF AEAD functions by key uuid

CREATE FUNCTION pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_ietf_encrypt(message, additional, nonce, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT
  STABLE
  SET search_path=''
;

GRANT EXECUTE ON FUNCTION
  pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

CREATE FUNCTION pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id pgsodium._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM pgsodium.valid_key v WHERE id = key_uuid;
  RETURN pgsodium.crypto_aead_ietf_decrypt(message, additional, nonce, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT
  STABLE
  SET search_path='';

GRANT EXECUTE ON FUNCTION
  crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

-- Transparent Column Encryption

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
        AS pattern_nonce_column
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
      100 AS priority
      FROM const k,
           pg_catalog.pg_seclabel sl
           JOIN pg_catalog.pg_class c ON sl.classoid = c.tableoid AND sl.objoid = c.oid
           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND sl.objsubid = a.attnum
     WHERE a.attnum > 0
           --  TODO : Filter out the catalog tables
       AND NOT a.attisdropped
       AND sl.label ilike 'ENCRYPT%'
       AND sl.provider = 'pgsodium'
  )
  SELECT
    DISTINCT ON (attrelid, attnum) *
    FROM rules_from_seclabels
   ORDER BY attrelid, attnum, priority DESC;

GRANT SELECT ON pgsodium.masking_rule TO PUBLIC;


CREATE FUNCTION pgsodium.has_mask(role regrole, source_name text)
  RETURNS boolean AS $$
  SELECT EXISTS(
    SELECT 1
      FROM pg_shseclabel
     WHERE  objoid = role
       AND provider = 'pgsodium'
       AND label ilike 'ACCESS%' || source_name || '%')
  $$ LANGUAGE sql;

-- Display all columns of the relation with the masking function (if any)
CREATE FUNCTION pgsodium.mask_columns(source_relid oid)
  RETURNS TABLE (attname name, key_id text, key_id_column text,
                 associated_column text, nonce_column text, format_type text)
AS $$
  SELECT
  a.attname,
  m.key_id,
  m.key_id_column,
  m.associated_column,
  m.nonce_column,
  m.format_type
  FROM pg_attribute a
  LEFT JOIN  pgsodium.masking_rule m
  ON m.attrelid = a.attrelid
  AND m.attname = a.attname
  WHERE  a.attrelid = source_relid
  AND    a.attnum > 0 -- exclude ctid, cmin, cmax
  AND    NOT a.attisdropped
  ORDER BY a.attnum;
$$ LANGUAGE sql;

-- get the "select filters" that will decrypt the real data of a table
CREATE FUNCTION pgsodium.decrypted_columns(
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
  FOR m IN SELECT * FROM pgsodium.mask_columns(relid) LOOP
    expression := expression || comma;
    IF m.key_id IS NULL AND m.key_id_column IS NULL THEN
      expression := expression || padding || quote_ident(m.attname);
    ELSE
      expression := expression || padding || quote_ident(m.attname) || E',\n';
      expression := expression || format(
        $f$
        pg_catalog.convert_from(
          pgsodium.crypto_aead_det_decrypt(
            pg_catalog.decode(%s, 'base64'),
            pg_catalog.convert_to(%s, 'utf8'),
            %s::uuid,
            %s
          ),
            'utf8') AS %s$f$,
            quote_ident(m.attname),
            coalesce(quote_ident(m.associated_column), quote_literal('')),
            coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
            coalesce(quote_ident(m.nonce_column), 'NULL'),
            'decrypted_' || quote_ident(m.attname)
      );
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

-- get the "insert filters" that will encrypt the real data of a table
CREATE FUNCTION pgsodium.encrypted_columns(
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
  FOR m IN SELECT * FROM pgsodium.mask_columns(relid) LOOP
    IF m.key_id IS NULL AND m.key_id_column is NULL THEN
      CONTINUE;
    ELSE
      expression := expression || comma;
      expression := expression || format(
        $f$%s = pg_catalog.encode(
          pgsodium.crypto_aead_det_encrypt(
            pg_catalog.convert_to(%s, 'utf8'),
            pg_catalog.convert_to(%s, 'utf8'),
            %s::uuid,
            %s
          ),
            'base64')$f$,
            'new.' || quote_ident(m.attname),
            'new.' || quote_ident(m.attname),
            COALESCE('new.' || quote_ident(m.associated_column), quote_literal('')),
            COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
            COALESCE('new.' || quote_ident(m.nonce_column), 'NULL')
      );
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

CREATE FUNCTION pgsodium.create_mask_view(relid oid, debug boolean = false) RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  view_name text;
  rule pgsodium.masking_rule;
BEGIN
  SELECT DISTINCT(quote_ident(relname)) INTO STRICT view_name
    FROM pg_class c, pg_seclabel sl
   WHERE relid = c.oid
     AND sl.classoid = c.tableoid
     AND sl.objoid = c.oid;

  source_name := relid::regclass;

  body = format(
    $c$
    DROP VIEW IF EXISTS pgsodium_masks.%s;
    CREATE VIEW pgsodium_masks.%s AS SELECT %s
    FROM %s;
    $c$,
    view_name,
    view_name,
    pgsodium.decrypted_columns(relid),
    source_name
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  body = format(
    $c$
    CREATE OR REPLACE FUNCTION pgsodium_masks.%s_encrypt_secret()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      AS $t$
    BEGIN
    %s;
    RETURN new;
    END;
    $t$;

    DROP TRIGGER IF EXISTS %s_encrypt_secret_trigger ON %s;

    CREATE TRIGGER %s_encrypt_secret_trigger
      BEFORE INSERT ON %s
      FOR EACH ROW
      EXECUTE FUNCTION pgsodium_masks.%s_encrypt_secret ();
    $c$,
    view_name,
    pgsodium.encrypted_columns(relid),
    view_name,
    source_name,
    view_name,
    source_name,
    view_name
  );
  if debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  PERFORM pgsodium.mask_role(oid::regrole, source_name, view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;

CREATE FUNCTION pgsodium.trg_mask_update()
RETURNS EVENT_TRIGGER AS
$$
BEGIN
  PERFORM pgsodium.update_masks();
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

-- Mask a specific role
CREATE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS
  $$
  DECLARE
  mask_schema REGNAMESPACE = 'pgsodium_masks';
  source_schema REGNAMESPACE = (regexp_split_to_array(source_name, '\.'))[1];
BEGIN
  EXECUTE format(
    'GRANT pgsodium_keyiduser TO %s',
    masked_role);

  EXECUTE format(
    'GRANT ALL ON %s.%s TO %s',
    mask_schema,
    view_name,
    masked_role);

  EXECUTE format(
    'ALTER ROLE %s SET search_path TO %s,%s,pg_catalog,public,pg_temp',
    masked_role,
    mask_schema,
    source_schema);
  RETURN;
END
$$
  LANGUAGE plpgsql
  SET search_path='pg_catalog'
;

CREATE FUNCTION pgsodium.update_masks(debug boolean = false)
RETURNS void AS
  $$
  declare
  rname text;
BEGIN
  PERFORM pgsodium.create_mask_view(c.oid, debug)
    FROM (SELECT distinct(c.oid)
            FROM pg_seclabel s, pg_class c, pg_namespace n
           WHERE s.objoid = c.oid
             AND c.relnamespace = n.oid
             AND c.relkind IN ('r', 'p', 'f') -- table, partition, or foreign
             AND s.provider = 'pgsodium') c;
  RETURN;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog'
;

CREATE EVENT TRIGGER pgsodium_trg_mask_update
  ON ddl_command_end
  WHEN TAG IN (
    'ALTER TABLE',
    'CREATE TABLE',
    'CREATE TABLE AS',
    'DROP TABLE',
    'ALTER MATERIALIZED VIEW',
    'CREATE MATERIALIZED VIEW',
    'DROP MATERIALIZED VIEW',
    'ALTER FOREIGN TABLE',
    'CREATE FOREIGN TABLE',
    'DROP FOREIGN TABLE',
    'SECURITY LABEL',
    'SELECT INTO'
  )
  EXECUTE PROCEDURE pgsodium.trg_mask_update()
;
