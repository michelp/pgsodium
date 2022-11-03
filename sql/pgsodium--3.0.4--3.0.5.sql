
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks GRANT ALL ON TABLES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks GRANT ALL ON SEQUENCES TO pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium_masks GRANT ALL ON FUNCTIONS TO pgsodium_keyiduser;

-- pgsodium_keyiduser can use all tables and sequences (functions are granted individually)
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON TABLES FROM pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON SEQUENCES FROM pgsodium_keyiduser;

ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON TABLES TO pgsodium_keyholder;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON SEQUENCES TO pgsodium_keyholder;

REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM pgsodium_keyiduser;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM pgsodium_keyiduser;

GRANT pgsodium_keyholder TO pgsodium_keymaker;  -- deprecating keyholder

GRANT ALL ON ALL TABLES IN SCHEMA pgsodium TO pgsodium_keymaker;
GRANT ALL ON ALL SEQUENCES IN SCHEMA pgsodium TO pgsodium_keymaker;

GRANT SELECT ON pgsodium.valid_key TO pgsodium_keyiduser;

DROP VIEW pgsodium.valid_key;
DROP FUNCTION pgsodium.create_key(text, pgsodium.key_type, bigint, bytea, timestamp, jsonb);
DELETE FROM pgsodium.key where status = 'default';

ALTER TYPE pgsodium.key_type ADD VALUE 'hmacsha512';
ALTER TYPE pgsodium.key_type ADD VALUE 'hmacsha256';
ALTER TYPE pgsodium.key_type ADD VALUE 'auth';
ALTER TYPE pgsodium.key_type ADD VALUE 'shorthash';
ALTER TYPE pgsodium.key_type ADD VALUE 'generichash';
ALTER TYPE pgsodium.key_type ADD VALUE 'kdf';
ALTER TYPE pgsodium.key_type ADD VALUE 'secretbox';
ALTER TYPE pgsodium.key_type ADD VALUE 'secretstream';
ALTER TYPE pgsodium.key_type ADD VALUE 'stream_xchacha20';

ALTER TABLE pgsodium.key ADD COLUMN raw_key bytea;
ALTER TABLE pgsodium.key ADD COLUMN raw_key_nonce bytea;
ALTER TABLE pgsodium.key ADD COLUMN parent_key uuid REFERENCES pgsodium.key(id);
ALTER TABLE pgsodium.key RENAME comment TO name;
ALTER TABLE pgsodium.key RENAME user_data TO associated_data;
ALTER TABLE pgsodium.key ALTER COLUMN associated_data TYPE text USING '';
ALTER TABLE pgsodium.key ALTER COLUMN associated_data SET DEFAULT 'associated';
ALTER TABLE pgsodium.key ALTER COLUMN key_id DROP NOT NULL;
ALTER TABLE pgsodium.key ALTER COLUMN key_context DROP NOT NULL;
ALTER TABLE pgsodium.key ALTER COLUMN expires TYPE timestamptz USING expires at time zone 'utc';
ALTER TABLE pgsodium.key ALTER COLUMN created TYPE timestamptz USING created at time zone 'utc';

ALTER TABLE pgsodium.key ADD CONSTRAINT pgsodium_key_unique_name UNIQUE (name);
ALTER TABLE pgsodium.key ADD CONSTRAINT pgsodium_raw CHECK (
  CASE WHEN raw_key IS NOT NULL
    THEN key_id IS NULL     AND key_context IS NULL     AND parent_key IS NOT NULL
    ELSE key_id IS NOT NULL AND key_context IS NOT NULL AND parent_key IS NULL
  END);

CREATE OR REPLACE VIEW pgsodium.valid_key AS
  SELECT id, name, status, key_type, key_id, key_context, created, expires, associated_data
    FROM pgsodium.key
   WHERE  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires < now() END;

GRANT SELECT ON pgsodium.valid_key TO pgsodium_keyiduser;

CREATE FUNCTION pgsodium.create_key(
  key_type pgsodium.key_type = 'aead-det',
  name text = NULL,
  raw_key bytea = NULL,
  raw_key_nonce bytea = NULL,
  parent_key uuid = NULL,
  key_context bytea = 'pgsodium',
  expires timestamptz = NULL,
  associated_data text = ''
) RETURNS pgsodium.valid_key
AS $$
DECLARE
  new_key pgsodium.key;
  valid_key pgsodium.valid_key;
BEGIN
  INSERT INTO pgsodium.key (key_id, key_context, key_type, raw_key,
  raw_key_nonce, parent_key, expires, name, associated_data)
      VALUES (
        CASE WHEN raw_key IS NULL THEN
            NEXTVAL('pgsodium.key_key_id_seq'::REGCLASS)
        ELSE NULL END,
        CASE WHEN raw_key IS NULL THEN
            key_context
        ELSE NULL END,
        key_type,
        raw_key,
        CASE WHEN raw_key IS NOT NULL THEN
            COALESCE(raw_key_nonce, pgsodium.crypto_aead_det_noncegen())
        ELSE NULL END,
        CASE WHEN parent_key IS NULL and raw_key IS NOT NULL THEN
            (pgsodium.create_key('aead-det')).id
        ELSE parent_key END,
        expires,
        name,
        associated_data)
    RETURNING * INTO new_key;
  SELECT * INTO valid_key FROM pgsodium.valid_key WHERE id = new_key.id;
  RETURN valid_key;
END;
$$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.create_key OWNER TO pgsodium_keymaker;
GRANT EXECUTE ON FUNCTION pgsodium.create_key TO pgsodium_keyiduser;

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

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, uuid) OWNER TO pgsodium_keymaker;

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

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

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

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, uuid) OWNER TO pgsodium_keymaker;

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

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

-- Auth

CREATE FUNCTION pgsodium.crypto_auth(message bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'auth';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth(message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth(message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth(bytea, uuid) OWNER TO pgsodium_keymaker;

CREATE FUNCTION crypto_auth_verify(mac bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'auth';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_auth_verify(mac, message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_auth_verify(mac, message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

-- Hash

CREATE FUNCTION pgsodium.crypto_shorthash(message bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'shorthash';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_shorthash(message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_shorthash(message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_shorthash(bytea, uuid) OWNER TO pgsodium_keymaker;

CREATE FUNCTION pgsodium.crypto_generichash(message bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'generichash';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_generichash(message, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_generichash(message, key.key_id, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_generichash(bytea, uuid) OWNER TO pgsodium_keymaker;

-- kdf

CREATE FUNCTION crypto_kdf_derive_from_key(subkey_size integer, subkey_id bigint, context bytea, primary_key uuid)
RETURNS bytea
AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = primary_key AND key_type = 'kdf';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_kdf_derive_from_key(subkey_size, subkey_id, context, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.derive_key(key.key_id, subkey_size, key.key_context);
END;

$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_kdf_derive_from_key(integer, bigint, bytea, uuid) OWNER TO pgsodium_keymaker;

  -- secretbox

CREATE OR REPLACE FUNCTION pgsodium.crypto_secretbox(message bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'secretbox';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_secretbox(message, nonce, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_secretbox(message, nonce, key.key_id, key.key_context);
END;
$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_secretbox(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

CREATE OR REPLACE FUNCTION pgsodium.crypto_secretbox_open(message bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'secretbox';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_secretbox_open(message, nonce, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_secretbox_open(message, nonce, key.key_id, key.key_context);
END;
$$
LANGUAGE plpgsql
STRICT STABLE
SECURITY DEFINER
SET search_path = '';

ALTER FUNCTION pgsodium.crypto_secretbox_open(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

-- Ext key support for DET and IETF

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-det';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.key_id, key.key_context);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path=''
  ;

ALTER FUNCTION pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-det';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.key_id, key.key_context);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

--- AEAD det with nonce

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS
$$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-det';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.decrypted_raw_key, nonce);
  END IF;
  RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.key_id, key.key_context, nonce);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path=''
  ;

ALTER FUNCTION pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea) OWNER TO pgsodium_keymaker;

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS
  $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-det';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.decrypted_raw_key, nonce);
  END IF;
  RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.key_id, key.key_context, nonce);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid, bytea) OWNER TO pgsodium_keymaker;

-- IETF AEAD functions by key uuid

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-ietf';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_ietf_encrypt(message, additional, nonce, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_aead_ietf_encrypt(message, additional, nonce, key.key_id, key.key_context);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STRICT
  STABLE
  SET search_path=''
;

ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

GRANT EXECUTE ON FUNCTION
  pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS
  $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key
    FROM pgsodium.decrypted_key v
  WHERE id = key_uuid AND key_type = 'aead-ietf';

  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_aead_ietf_decrypt(message, additional, nonce, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_aead_ietf_decrypt(message, additional, nonce, key.key_id, key.key_context);
END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STRICT
  STABLE
  SET search_path='';

ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) OWNER TO pgsodium_keymaker;

GRANT EXECUTE ON FUNCTION
  pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  TO pgsodium_keyiduser;

-- bytea and extended associated data support for encrypted columns

DROP VIEW pgsodium.masking_rule CASCADE;

CREATE OR REPLACE VIEW pgsodium.masking_rule AS
  WITH const AS (
    SELECT
      'encrypt +with +key +id +([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
        AS pattern_key_id,
      'encrypt +with +key +column +(\w+)'
        AS pattern_key_id_column,
      '(?<=associated) +\(([\w, ]+)\)'
        AS pattern_associated_columns,
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
      (regexp_match(sl.label, k.pattern_associated_columns, 'i'))[1] AS associated_columns,
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
  m.associated_columns,
  m.nonce_column,
  m.format_type
  FROM pg_attribute a
  LEFT JOIN  pgsodium.masking_rule m
  ON m.attrelid = a.attrelid
  AND m.attname = a.attname
  WHERE  a.attnum > 0 -- exclude ctid, cmin, cmax
  AND    NOT a.attisdropped
  ORDER BY a.attnum;

CREATE OR REPLACE FUNCTION pgsodium.quote_assoc(text, boolean = false)
RETURNS text
AS $$
    WITH a AS (SELECT array_agg(CASE WHEN $2 THEN
                                    'new.' || quote_ident(trim(v))
                                ELSE quote_ident(trim(v)) END) as r
               FROM regexp_split_to_table($1, '\s*,\s*') as v)
    SELECT array_to_string(a.r, '::text || ') || '::text' FROM a;
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION pgsodium.encrypted_columns(relid OID)
RETURNS TEXT AS
$$
DECLARE
    m RECORD;
    expression TEXT;
    comma TEXT;
BEGIN
  expression := '';
  comma := E'        ';
  FOR m IN SELECT * FROM pgsodium.mask_columns where attrelid = relid LOOP
    IF m.key_id IS NULL AND m.key_id_column is NULL THEN
      CONTINUE;
    ELSE
      expression := expression || comma;
      IF m.format_type = 'text' THEN
          expression := expression || format(
            $f$%s = CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.encode(
              pgsodium.crypto_aead_det_encrypt(
                pg_catalog.convert_to(%s, 'utf8'),
                pg_catalog.convert_to((%s)::text, 'utf8'),
                %s::uuid,
                %s
              ),
                'base64') END$f$,
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
                        pgsodium.crypto_aead_det_encrypt(%s::bytea, pg_catalog.convert_to((%s)::text, 'utf8'),
                %s::uuid,
                %s
              ) END
              $f$,
                'new.' || quote_ident(m.attname),
                COALESCE('new.' || quote_ident(m.key_id_column), quote_literal(m.key_id)),
                'new.' || quote_ident(m.attname),
                COALESCE(pgsodium.quote_assoc(m.associated_columns, true), quote_literal('')),
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
            CASE WHEN %s IS NULL THEN NULL ELSE pg_catalog.convert_from(
              pgsodium.crypto_aead_det_decrypt(
                pg_catalog.decode(%s, 'base64'),
                pg_catalog.convert_to((%s)::text, 'utf8'),
                %s::uuid,
                %s
              ),
                'utf8') END AS %s$f$,
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(pgsodium.quote_assoc(m.associated_columns), quote_literal('')),
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                coalesce(quote_ident(m.nonce_column), 'NULL'),
                'decrypted_' || quote_ident(m.attname)
          );
      ELSIF m.format_type = 'bytea' THEN
          expression := expression || format(
            $f$
            CASE WHEN %s IS NULL THEN NULL ELSE pgsodium.crypto_aead_det_decrypt(
                %s::bytea,
                pg_catalog.convert_to((%s)::text, 'utf8'),
                %s::uuid,
                %s
              ) END AS %s$f$,
                coalesce(quote_ident(m.key_id_column), quote_literal(m.key_id)),
                quote_ident(m.attname),
                coalesce(pgsodium.quote_assoc(m.associated_columns), quote_literal('')),
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

CREATE OR REPLACE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS
  $$
BEGIN
  EXECUTE format('GRANT pgsodium_keyiduser TO %s', masked_role);
  EXECUTE format('GRANT ALL ON %s TO %s', view_name, masked_role);
  RETURN;
END
$$
LANGUAGE plpgsql
SET search_path=''
;

CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false) RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  rule pgsodium.masking_rule;
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
    pgsodium.decrypted_columns(relid),
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
    pgsodium.encrypted_columns(relid),
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
        'pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid)',
        'pgsodium.crypto_auth(bytea, uuid)',
        'pgsodium.crypto_auth_verify(bytea, bytea, uuid)',
        'pgsodium.crypto_shorthash(bytea, uuid)',
        'pgsodium.crypto_generichash(bytea, uuid)',
        'pgsodium.crypto_kdf_derive_from_key(integer, bigint, bytea, uuid)',
        'pgsodium.crypto_secretbox(bytea, bytea, uuid)',
        'pgsodium.crypto_secretbox_open(bytea, bytea, uuid)',
        'pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid)',
        'pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid)',
        'pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea)',
        'pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid, bytea)',
        'pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid)',
        'pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid)'
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
    IS 'ENCRYPT WITH KEY COLUMN parent_key ASSOCIATED (id, associated_data) NONCE raw_key_nonce';

ALTER EXTENSION pgsodium DROP VIEW pgsodium.decrypted_key;
GRANT SELECT ON pgsodium.decrypted_key TO pgsodium_keymaker;
