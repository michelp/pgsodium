
-- All roles cannot execute functions in pgsodium
REVOKE ALL ON SCHEMA @extschema@ FROM PUBLIC;
-- But they can see the objects in pgsodium
GRANT USAGE ON SCHEMA @extschema@ TO PUBLIC;

-- By default, public can't use any table, functions, or sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@ REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@ REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@ REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- pgsodium_keyiduser can use all tables and sequences (functions are granted individually)
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@ GRANT ALL ON TABLES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@ GRANT ALL ON SEQUENCES TO pgsodium_keyiduser;

-- Create a schema to hold the masking views
CREATE SCHEMA @extschema@_masks;
-- Revoke all from public on that schema
REVOKE ALL ON SCHEMA @extschema@_masks FROM PUBLIC;
-- pgsodium_keyiduser can see objects in the schema.
GRANT USAGE ON SCHEMA @extschema@_masks TO pgsodium_keyiduser;

-- By default public can't use any tables, functions, or sequences in the mask schema
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks REVOKE ALL ON SEQUENCES FROM PUBLIC;
-- pgsodium can see the views
-- individual roles will be specifically granted view access when they are SECURITY LABELed
ALTER DEFAULT PRIVILEGES IN SCHEMA @extschema@_masks GRANT ALL ON TABLES TO pgsodium_keyiduser;

-- Misc functions

CREATE OR REPLACE FUNCTION @extschema@.version()
RETURNS text AS
$$
  SELECT extversion FROM pg_extension WHERE extname = 'pgsodium';
$$
  LANGUAGE SQL
  SET search_path='pg_catalog'
  ;

-- Internal Key Management

CREATE TYPE @extschema@.key_status AS ENUM (
  'default',
  'valid',
  'invalid',
  'expired'
);

CREATE TYPE @extschema@.key_type AS ENUM (
  'aead-ietf',
  'aead-det'
);

CREATE TABLE @extschema@.key (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status @extschema@.key_status DEFAULT 'valid',
  created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires timestamp,
  key_type @extschema@.key_type,
  key_id bigserial NOT NULL,
  key_context bytea NOT NULL DEFAULT 'pgsodium' CHECK (length(key_context) = 8),
  comment text,
  user_data jsonb
);

SELECT pg_catalog.pg_extension_config_dump('@extschema@.key', '');

GRANT SELECT ON @extschema@.key TO pgsodium_keyiduser;
GRANT INSERT, UPDATE, DELETE ON @extschema@.key TO pgsodium_keymaker;

CREATE INDEX ON @extschema@.key (status)
  WHERE (status IN ('valid', 'default'));

CREATE UNIQUE INDEX ON @extschema@.key (status)
  WHERE (status = 'default');

CREATE UNIQUE INDEX ON @extschema@.key (key_id, key_context);

COMMENT ON TABLE @extschema@.key IS
  'This table holds metadata for derived keys given a key_id '
  'and key_context. The raw key is never stored.';

CREATE VIEW @extschema@.valid_key AS
  SELECT
    *
    FROM
      @extschema@.key
   WHERE
  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires < now() END;

CREATE FUNCTION @extschema@.create_key(
  key_type @extschema@.key_type,
  comment text = null,
  key_id bigint = null,
  key_context bytea = 'pgsodium',
  expires timestamp = null,
  user_data jsonb = null) RETURNS @extschema@.key AS
  $$
  INSERT INTO @extschema@.key (key_id, key_context, expires, comment, user_data)
  VALUES (case  when key_id is null then nextval('@extschema@.key_key_id_seq'::regclass) else key_id
          end,
          key_context,
          expires,
          comment,
          user_data) RETURNING *
  $$ LANGUAGE SQL
  SET search_path='pg_catalog'
  ;

-- Deterministic AEAD functions by key uuid

CREATE TYPE @extschema@._key_id_context AS (
  key_id bigint,
  key_context bytea
  );

CREATE FUNCTION @extschema@.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key_id @extschema@._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM @extschema@.valid_key v WHERE id = key_uuid;
  RETURN @extschema@.crypto_aead_det_encrypt(message, additional, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT
  STABLE
  SET search_path=''
  ;

GRANT EXECUTE ON FUNCTION
  @extschema@.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

CREATE FUNCTION @extschema@.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id @extschema@._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM @extschema@.valid_key v WHERE id = key_uuid;
  RETURN @extschema@.crypto_aead_det_decrypt(message, additional, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT
  STABLE
  SET search_path='';

GRANT EXECUTE ON FUNCTION
  crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

-- IETF AEAD functions by key uuid

CREATE FUNCTION @extschema@.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id @extschema@._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM @extschema@.valid_key v WHERE id = key_uuid;
  RETURN @extschema@.crypto_aead_ietf_encrypt(message, additional, nonce, key_id.key_id, key_id.key_context);
END;
  $$
  LANGUAGE plpgsql
  STRICT
  STABLE
  SET search_path=''
;

GRANT EXECUTE ON FUNCTION
  @extschema@.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

CREATE FUNCTION @extschema@.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key_id @extschema@._key_id_context;
BEGIN
  SELECT v.key_id, v.key_context INTO STRICT key_id FROM @extschema@.valid_key v WHERE id = key_uuid;
  RETURN @extschema@.crypto_aead_ietf_decrypt(message, additional, nonce, key_id.key_id, key_id.key_context);
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

CREATE OR REPLACE VIEW @extschema@.masking_rule AS
  WITH const AS (
    SELECT
      -- #" is the escape-double-quote separator
      '%ENCRYPT +WITH +KEY +ID +COLUMN +#"%#'::TEXT
        AS pattern_key_id_column,
      'ENCRYPT +WITH +KEY +ID +#"%#" ?'::TEXT
        AS pattern_key_id
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
      trim(substring(sl.label FROM k.pattern_key_id_column FOR '#'))
        AS key_id_column,
      trim(substring(sl.label FROM k.pattern_key_id FOR '#'))
        AS key_id,
      100 AS priority -- high priority for the security label syntax
      FROM const k,
           pg_catalog.pg_seclabel sl
           JOIN pg_catalog.pg_class c ON sl.classoid = c.tableoid AND sl.objoid = c.oid
           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND sl.objsubid = a.attnum
     WHERE a.attnum > 0
           --  TODO : Filter out the catalog tables
       AND NOT a.attisdropped
       AND (sl.label SIMILAR TO k.pattern_key_id_column ESCAPE '#'
            OR sl.label SIMILAR TO k.pattern_key_id ESCAPE '#'
       )
       AND sl.provider = 'pgsodium' -- this is hard-coded in pgsodium.c
  )
  -- DISTINCT will keep just the 1st rule for each column based on priority,
  SELECT
    DISTINCT ON (attrelid, attnum) attrelid, attnum, relnamespace, relname, attname, format_type, col_description, priority,
    COALESCE(key_id_column, quote_literal(key_id)) AS key_id
    FROM rules_from_seclabels
   ORDER BY attrelid, attnum, priority DESC;

GRANT SELECT ON @extschema@.masking_rule TO PUBLIC;


CREATE FUNCTION @extschema@.has_mask(
  role REGROLE
)
  RETURNS BOOLEAN AS
  $$
  SELECT bool_or(m.masked)
  FROM (
    -- Rule from SECURITY LABEL
    SELECT label ILIKE 'ENCRYPT' AS masked
      FROM pg_shseclabel
     WHERE  objoid = role
       AND provider = 'pgsodium' -- this is hard coded in pgsodium.c
            UNION
       -- return FALSE if the SELECT above is empty
    SELECT FALSE as masked --
  ) AS m
  $$
  LANGUAGE SQL
  STABLE
  SET search_path='pg_catalog'
  ;

-- Display all columns of the relation with the masking function (if any)
CREATE FUNCTION @extschema@.mask_columns(source_relid oid)
RETURNS TABLE (attname name, key_id text, format_type text) AS
$$
  SELECT
  a.attname,
  m.key_id,
  m.format_type
  FROM pg_attribute a
  LEFT JOIN  @extschema@.masking_rule m
  ON m.attrelid = a.attrelid
  AND m.attname = a.attname
  WHERE  a.attrelid = source_relid
  AND    a.attnum > 0 -- exclude ctid, cmin, cmax
  AND    NOT a.attisdropped
  ORDER BY a.attnum;
$$
  LANGUAGE SQL
  VOLATILE
  SET search_path='pg_catalog'
;

-- get the "select filters" that will decrypt the real data of a table
CREATE FUNCTION @extschema@.decrypted_columns(
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
  comma := E'\n        ';
  FOR m IN SELECT * FROM @extschema@.mask_columns(relid)
    LOOP
    expression := expression || comma;
    IF m.key_id IS NULL THEN
      expression := expression || quote_ident(m.attname);
    ELSE
      expression := expression || format(
        $f$pg_catalog.convert_from(
          @extschema@.crypto_aead_det_decrypt(
            pg_catalog.decode(%s, 'base64'),
            '',
            %s::uuid),
            'utf8') AS %s
            $f$,
            quote_ident(m.attname),
            m.key_id,
            quote_ident(m.attname));
    END IF;
    comma := E',\n        ';
  END LOOP;
  RETURN expression;
END
$$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path=''
;

-- get the "insert filters" that will encrypt the real data of a table
CREATE FUNCTION @extschema@.encrypted_columns(
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
  comma := E'\n        ';
  FOR m IN SELECT * FROM @extschema@.mask_columns(relid)
    LOOP
    expression := expression || comma;
    IF m.key_id IS NOT NULL THEN
      expression := expression || format(
        $f$%s = pg_catalog.encode(
          @extschema@.crypto_aead_det_encrypt(
            pg_catalog.convert_to(%s, 'utf8'),
            ''::bytea,
            %s::uuid),
            'base64')
            $f$,
            'new.' || quote_ident(m.attname),
            'new.' || quote_ident(m.attname),
            m.key_id);
      comma := E',\n        ';
    END IF;
  END LOOP;
  RETURN expression;
END
$$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path=''
  ;
  
CREATE FUNCTION @extschema@.mask_create_view(
  relid OID,
  drop_view boolean = false
)
RETURNS BOOLEAN AS
  $$
  DECLARE
  body text;
  source_name text;
  view_name text;
  rule @extschema@.masking_rule;
BEGIN
  if drop_view THEN
  raise notice '%', format(
    $drop$
    DROP VIEW @extschema@_masks.%s
    $drop$,
    relid::regclass);
  END IF;

  SELECT quote_ident(relname) INTO STRICT view_name
    FROM pg_class c, pg_seclabel sl
   WHERE relid = c.oid
     AND sl.classoid = c.tableoid
     AND sl.objoid = c.oid;

  source_name := relid::regclass;

  body = format(
    $c$
    CREATE OR REPLACE VIEW @extschema@_masks.%s AS SELECT %s FROM %s;
    $c$,
    view_name,
    @extschema@.decrypted_columns(relid),
    source_name
  );
  RAISE NOTICE '%', body;
  EXECUTE body;

  body = format(
    $c$
    CREATE OR REPLACE FUNCTION @extschema@_masks.%s_encrypt_secret()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      AS $t$
    BEGIN
    %s;
    RETURN new;
    END;
    $t$;

    CREATE TRIGGER %s_encrypt_secret_trigger
      BEFORE INSERT ON %s
      FOR EACH ROW
      EXECUTE FUNCTION @extschema@_masks.%s_encrypt_secret ();
    $c$,
    view_name,
    @extschema@.encrypted_columns(relid),
    view_name,
    source_name,
    view_name
  );
  RAISE NOTICE '%', body;
  EXECUTE body;
  RETURN TRUE;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;

-- This is run after any changes in the data model
CREATE FUNCTION @extschema@.trg_mask_update()
RETURNS EVENT_TRIGGER AS
$$
BEGIN
  PERFORM @extschema@.update_masks();
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;

-- Mask a specific role
CREATE FUNCTION @extschema@.mask_role(
  maskedrole REGROLE
)
RETURNS BOOLEAN AS
$$
DECLARE
  maskschema REGNAMESPACE = '@extschema@_masks';
BEGIN

  -- Allow role to use pgsodium
  EXECUTE format(
    'GRANT USAGE ON SCHEMA @extschema@ TO %s',
    maskedrole);

  EXECUTE format(
    'GRANT SELECT ON ALL TABLES IN SCHEMA @extschema@ TO %s',
    maskedrole);

  EXECUTE format(
    'GRANT SELECT ON ALL SEQUENCES IN SCHEMA @extschema@ TO %s',
    maskedrole);

  EXECUTE format(
    'GRANT USAGE ON SCHEMA %s TO %s',
    maskschema,
    maskedrole);

  EXECUTE format(
    'GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s',
    maskschema,
    maskedrole);

  EXECUTE format(
    'ALTER ROLE %s SET search_path TO %s,%s;',
    maskedrole,
    maskschema,
    current_setting('search_path'));
  RETURN TRUE;
END
$$
  LANGUAGE plpgsql
  SET search_path='pg_catalog'
;

CREATE FUNCTION @extschema@.update_masks(drop_views boolean = false)
RETURNS BOOLEAN AS
$$
BEGIN
  -- Walk through all tables in the source schema
  -- and build a dynamic masking view
  PERFORM @extschema@.mask_create_view(c.oid, drop_views)
    FROM pg_seclabel s, pg_class c, pg_namespace n
    WHERE s.objoid = c.oid
    AND c.relnamespace = n.oid
    AND c.relkind IN ('r', 'p', 'f') -- table, partition, or foreign
    AND s.provider = 'pgsodium';

  -- Walk through all masked roles and apply the restrictions
  PERFORM @extschema@.mask_role(oid::regrole)
  FROM pg_roles WHERE @extschema@.has_mask(oid::regrole);

  RETURN TRUE;
END
$$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog'
;

CREATE EVENT TRIGGER @extschema@_trg_mask_update
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
  EXECUTE PROCEDURE @extschema@.trg_mask_update()
;
