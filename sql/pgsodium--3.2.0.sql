-- TODO: check namespaces in funcs body
-- TODO: check strictiness of the functions

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgsodium" to load this file. \quit

COMMENT ON EXTENSION pgsodium IS
'Pgsodium is a modern cryptography library for Postgres.';

--==============================================================================
--                               ROLES
--==============================================================================

/* */
DO $$
  DECLARE
    new_role text;
  BEGIN
    FOREACH new_role IN ARRAY
        ARRAY['pgsodium_keyiduser',
              'pgsodium_keyholder',
              'pgsodium_keymaker']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = new_role) THEN
            EXECUTE pg_catalog.format($i$
                CREATE ROLE %I WITH
                NOLOGIN
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                INHERIT
                NOREPLICATION
                CONNECTION LIMIT -1
                $i$, new_role);
        END IF;
    END LOOP;
  END
$$;

GRANT pgsodium_keyholder TO pgsodium_keymaker;  -- deprecating keyholder
GRANT pgsodium_keyiduser TO pgsodium_keymaker;
GRANT pgsodium_keyiduser TO pgsodium_keyholder;

--==============================================================================
--                              TRIGGERS
--==============================================================================

CREATE FUNCTION pgsodium.tg_tce_encrypt_using_key_col()
  RETURNS trigger
  AS '$libdir/pgsodium'
  LANGUAGE C
  SECURITY DEFINER;

CREATE FUNCTION pgsodium.tg_tce_encrypt_using_key_id()
  RETURNS trigger
  AS '$libdir/pgsodium'
  LANGUAGE C
  SECURITY DEFINER;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * tce_update_view(oid)
 *
 * Build if needed:
 * - decrypting view
 */
CREATE FUNCTION pgsodium.tce_update_view(relid oid)
  RETURNS void AS $$
    DECLARE
      r record;
      origrelpath text;
      viewname text;
      body text = '';
      enc_cols text[];
      dec_col text;
      dec_col_alias text;
      ad text;
      view_owner regrole = session_user;
      privs aclitem[];
    BEGIN
      SELECT
        pg_catalog.format('%I.%I', n.nspname, c.relname)
        INTO STRICT origrelpath
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
      WHERE c.oid = tce_update_view.relid;

      FOR r IN
        SELECT *
        FROM pgsodium.masking_rule AS mr
        WHERE mr.attrelid = tce_update_view.relid
      LOOP
        IF viewname IS NULL THEN
          viewname = r.view_name;
        END IF;

        dec_col = pg_catalog.format('%I', r.attname);
        dec_col_alias = 'decrypted_' || r.attname;

        IF r.key_id IS NOT NULL THEN
          dec_col = pg_catalog.format('%s, UUID %L', dec_col, r.key_id);
        ELSIF r.key_id_column IS NOT NULL THEN
          dec_col = pg_catalog.format('%s, %I', dec_col, r.key_id_column);
        ELSE
          enc_cols = enc_cols || ARRAY[
              pg_catalog.format('NULL AS %I', dec_col_alias)
          ];
          CONTINUE;
        END IF;

        IF r.nonce_column IS NOT NULL THEN
          dec_col = pg_catalog.format('%s, %I', dec_col, r.nonce_column);
        END IF;

        IF r.associated_columns IS NOT NULL THEN
          WITH a AS (
              SELECT pg_catalog.array_agg( format('%I::text', trim(v)) ) AS r
              FROM pg_catalog.regexp_split_to_table(r.associated_columns,
                                                    '\s*,\s*') as v
          )
          SELECT pg_catalog.array_to_string(a.r, ' || ') INTO ad
          FROM a;

          dec_col = pg_catalog.format('%s, ad => %s', dec_col, ad);
        END IF;

        enc_cols = enc_cols
            || pg_catalog.format(E'pgsodium.tce_decrypt_col(%s) AS %I',
                                 dec_col, dec_col_alias);
      END LOOP;

      IF (viewname IS NULL) THEN
        RAISE NOTICE 'skip decrypting view: relation % has no encrypted columns', relid::regclass;
        RETURN;
      END IF;

      body = pg_catalog.format('
        DROP VIEW IF EXISTS %s;
        CREATE VIEW %1$s AS
           SELECT *,
             %s
           FROM %s;
        ALTER VIEW %1$s OWNER TO %4$I;
        REVOKE ALL ON %1$s FROM public;',
        viewname, -- supposed to be already escaped
        array_to_string(enc_cols, E',\n'),
        origrelpath,
        view_owner
      );

      IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
        RAISE NOTICE '%', body;
      END IF;

      EXECUTE body;

      BEGIN
        SELECT relacl INTO STRICT privs
        FROM pg_catalog.pg_class
        WHERE oid = rule.view_name::regclass::oid;
      EXCEPTION
        WHEN undefined_table THEN
          SELECT relacl INTO STRICT privs
          FROM pg_catalog.pg_class
          WHERE oid = relid;
      END;

      -- FIXME: missing revoke DDL?
      FOR r IN SELECT * FROM pg_catalog.aclexplode(privs) LOOP
        body = pg_catalog.format( 'GRANT %s ON %s TO %I',
          r.privilege_type,
          viewname, -- supposed to be already escaped
          r.grantee::regrole::text
        );

        IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
          RAISE NOTICE '%', body;
        END IF;

        EXECUTE body;
      END LOOP;

      PERFORM pgsodium.mask_role(oid::regrole, origrelpath, viewname)
      FROM pg_catalog.pg_roles
      WHERE pgsodium.has_mask(oid::regrole, origrelpath);
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * tce_update_attr_tg(oid, integer)
 *
 * Build if needed:
 * - encrypting triggers on tables with encrypted cols
 * - decrypting view
 */
CREATE FUNCTION pgsodium.tce_update_attr_tg(relid oid, attnum integer)
  RETURNS void AS $$
    DECLARE
      body text;
      rule pgsodium.masking_rule;
      raw_key bytea;
      key_id bigint;
      tgname text;
      tgf text;
      tgargs text;
      attname text;
    BEGIN
      -- get encryption rules for given field
      SELECT DISTINCT * INTO STRICT rule
      FROM pgsodium.masking_rule AS mr
      WHERE mr.attrelid = relid
        AND mr.attnum = tce_update_attr_tg.attnum;

     tgname = 'encrypt_' || rule.attname;
     tgargs = pg_catalog.quote_literal(rule.attname);

      IF rule.key_id_column IS NOT NULL THEN
        tgf = 'tg_tce_encrypt_using_key_col';
        tgargs = pg_catalog.format('%s, %L', tgargs, rule.key_id_column);
      ELSIF rule.key_id IS NOT NULL THEN
        tgf = 'tg_tce_encrypt_using_key_id';
        tgargs = pg_catalog.format('%s, %L', tgargs, rule.key_id);
      ELSE
          -- FIXME trigger set col to NULL
      END IF;

      IF rule.nonce_column IS NOT NULL THEN
        tgargs = pg_catalog.format('%s, %L', tgargs, rule.nonce_column);
      END IF;

      IF rule.associated_columns IS NOT NULL THEN
        IF rule.nonce_column IS NULL THEN
          /*
           * empty nonce is required because associated cols starts at
           * the 4th argument.
           */
          tgargs = pg_catalog.format('%s, %L', tgargs, '');
        END IF;

        FOR attname IN
            SELECT pg_catalog.regexp_split_to_table(rule.associated_columns,
                                                    '\s*,\s*')
        LOOP
            tgargs = pg_catalog.format('%s, %L', tgargs, attname);
        END LOOP;
      END IF;

      body = pg_catalog.format('
          DROP TRIGGER IF EXISTS %1$I ON %3$I.%4$I;

          CREATE TRIGGER %1$I BEFORE INSERT OR UPDATE OF %2$I
            ON %3$I.%4$I FOR EACH ROW EXECUTE FUNCTION
            pgsodium.%5$I(%6$s);',
        tgname,       -- 1
        rule.attname, -- 2
        rule.nspname, -- 3
        rule.relname, -- 4
        tgf,          -- 5
        tgargs        -- 6
      );

      IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
        RAISE NOTICE '%', body;
      END IF;

      EXECUTE body;

      PERFORM pgsodium.disable_security_label_trigger();
      PERFORM pgsodium.tce_update_view(relid);
      PERFORM pgsodium.enable_security_label_trigger();

      RETURN;
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

/*
 * tg_tce_update()
 */
CREATE FUNCTION pgsodium.tg_tce_update()
  RETURNS EVENT_TRIGGER
  AS $$
    DECLARE r record;
    BEGIN
      IF ( SELECT bool_or(in_extension) FROM pg_event_trigger_ddl_commands() )
      THEN
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
        )
      LOOP
        IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
          RAISE NOTICE 'trg_mask_update: classid: %, objid: %, objsubid: %, tag: %, obj_type: %, schema: %, identity: %, in_ext: %',
            r.classid, r.objid, r.objsubid, r.command_tag, r.object_type,
            r.schema_name, r.object_identity, r.in_extension;
        END IF;

        IF r.object_type = 'table column' AND r.objsubid <> 0 THEN
          /*
           * Create/update encryption trigger for given attribute. This triggers
           * the creation/update of the related decrypting view as well.
           */
          PERFORM pgsodium.tce_update_attr_tg(r.objid, r.objsubid);
        ELSIF r.object_type = 'table' AND r.objsubid = 0 THEN
          /*
           * Create/update the view on given table
           */
           PERFORM pgsodium.tce_update_view(r.objid);
        END IF;
      END LOOP;
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/* */
CREATE EVENT TRIGGER pgsodium_tg_tce_update
  ON ddl_command_end
  WHEN TAG IN (
    'SECURITY LABEL',
    'ALTER TABLE'
  )
  EXECUTE PROCEDURE pgsodium.tg_tce_update();

--==============================================================================
--                               TYPES
--==============================================================================

/* */
CREATE TYPE pgsodium.crypto_box_keypair AS (public bytea, secret bytea);

/* */
CREATE TYPE pgsodium.crypto_sign_keypair AS (public bytea, secret bytea);

/* */
CREATE TYPE pgsodium.crypto_kx_keypair AS (public bytea, secret bytea);

/* */
CREATE TYPE pgsodium.crypto_kx_session AS (rx bytea, tx bytea);

/* */
CREATE TYPE pgsodium.crypto_signcrypt_state_key AS (state bytea, shared_key bytea);

/* */
CREATE TYPE pgsodium.crypto_signcrypt_keypair AS (public bytea, secret bytea);

/* Internal Key Management */
CREATE TYPE pgsodium.key_status AS ENUM (
  'default',
  'valid',
  'invalid',
  'expired'
);

/* */
CREATE TYPE pgsodium.key_type AS ENUM (
  'aead-ietf',
  'aead-det',
  'hmacsha512',
  'hmacsha256',
  'auth',
  'shorthash',
  'generichash',
  'kdf',
  'secretbox',
  'secretstream',
  'stream_xchacha20'
);

/* Deterministic AEAD functions by key uuid */
CREATE TYPE pgsodium._key_id_context AS (
  key_id bigint,
  key_context bytea
);


--==============================================================================
--                               TABLE
--==============================================================================

/* */
CREATE TABLE pgsodium.key (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status pgsodium.key_status DEFAULT 'valid',
  created timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires timestamptz,
  key_type pgsodium.key_type,
  key_id bigserial,
  key_context bytea DEFAULT 'pgsodium' CHECK (length(key_context) = 8),
  "name" text UNIQUE,
  associated_data text DEFAULT 'associated',
  raw_key bytea,
  raw_key_nonce bytea,
  parent_key uuid REFERENCES pgsodium.key(id),
  -- This is for bw compat with old dumps that don't go through the UPDATE TO process
  "comment" text,
  -- deprecated for b/w compat with <= 3.0.4
  user_data text,
  CHECK (
    CASE WHEN raw_key IS NOT NULL
      THEN key_id IS NULL     AND key_context IS NULL     AND parent_key IS NOT NULL
      ELSE key_id IS NOT NULL AND key_context IS NOT NULL AND parent_key IS NULL
    END
  )
);

-- serial pseudo-type force NOT NULL but we allow them.
ALTER TABLE pgsodium.key ALTER COLUMN key_id DROP NOT NULL;

-- FIXME: owner?
-- FIXME: revoke?
GRANT SELECT ON pgsodium.key TO pgsodium_keyiduser;
GRANT INSERT, UPDATE, DELETE ON pgsodium.key TO pgsodium_keymaker;

CREATE INDEX ON pgsodium.key (status) WHERE status IN ('valid', 'default');
CREATE UNIQUE INDEX ON pgsodium.key (status) WHERE status = 'default';
CREATE UNIQUE INDEX ON pgsodium.key (key_id, key_context, key_type);

COMMENT ON TABLE pgsodium.key IS
  'This table holds metadata for derived keys given a key_id '
  'and key_context. The raw key is never stored.';

SELECT pg_catalog.pg_extension_config_dump('pgsodium.key', '');

--==============================================================================
--                                VIEWS
--==============================================================================

/* */ 
CREATE VIEW pgsodium.valid_key AS
  SELECT id, name, status, key_type, key_id, key_context, created, expires, associated_data
    FROM pgsodium.key
   WHERE  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires > now() END;

-- FIXME: owner?
-- FIXME: revoke?
GRANT SELECT ON pgsodium.valid_key TO pgsodium_keyiduser;

/*
 * FIXME: bug: the view path given by the user in the security label might not
 *        be quoted correctly.
 */
CREATE VIEW pgsodium.masking_rule AS
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
        AS pattern_view_name
  ),
  rules_from_seclabels AS (
    SELECT
      sl.objoid AS attrelid,
      sl.objsubid  AS attnum,
      c.relnamespace,
      c.relname,
      n.nspname,
      a.attname,
      pg_catalog.format_type(a.atttypid, a.atttypmod),
      sl.label AS col_description,
      (regexp_match(sl.label, k.pattern_key_id_column, 'i'))[1] AS key_id_column,
      (regexp_match(sl.label, k.pattern_key_id, 'i'))[1] AS key_id,
      (regexp_match(sl.label, k.pattern_associated_columns, 'i'))[1] AS associated_columns,
      (regexp_match(sl.label, k.pattern_nonce_column, 'i'))[1] AS nonce_column,
      coalesce((regexp_match(sl2.label, k.pattern_view_name, 'i'))[1],
               quote_ident(nspname) || '.' || quote_ident('decrypted_' || c.relname)) AS view_name,
      100 AS priority
      FROM const k,
           pg_catalog.pg_seclabel sl
           JOIN pg_catalog.pg_class c ON sl.classoid = c.tableoid AND sl.objoid = c.oid
           JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid AND sl.objoid = c.oid
           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND sl.objsubid = a.attnum
           LEFT JOIN pg_catalog.pg_seclabel sl2 ON sl2.objoid = c.oid AND sl2.objsubid = 0
     WHERE a.attnum > 0
       AND n.nspname <> 'pg_catalog'
       AND NOT a.attisdropped
       AND sl.label ILIKE 'ENCRYPT%'
       AND sl.provider = 'pgsodium'
  )
  SELECT
    DISTINCT ON (attrelid, attnum) *
    FROM rules_from_seclabels
   ORDER BY attrelid, attnum, priority DESC;

-- FIXME: owner?
-- FIXME: revoke?
GRANT SELECT ON pgsodium.masking_rule TO PUBLIC;

--==============================================================================
--                               FUNCTIONS
--==============================================================================

/*
 * create_key(pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamptz, text)
 *
 * Insert new key in "pgsodium.valid_key" table.
 */
CREATE FUNCTION pgsodium.create_key(
    key_type pgsodium.key_type = 'aead-det',
    name text = NULL,
    raw_key bytea = NULL,
    raw_key_nonce bytea = NULL,
    parent_key uuid = NULL,
    key_context bytea = 'pgsodium',
    expires timestamptz = NULL,
    associated_data text = ''
  )
  RETURNS pgsodium.valid_key
  AS $$
    DECLARE
      new_key pgsodium.key;
      valid_key pgsodium.valid_key;
    BEGIN
      INSERT INTO pgsodium.key (
        key_id, key_context, key_type, raw_key,
        raw_key_nonce, parent_key, expires, name, associated_data
      )
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
        associated_data
      )
      RETURNING * INTO new_key;

      SELECT * INTO valid_key
      FROM pgsodium.valid_key
      WHERE id = new_key.id;

      RETURN valid_key;
    END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.create_key(pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamptz, text) OWNER TO pgsodium_keymaker;
-- FIXME: REVOKE?
GRANT EXECUTE ON FUNCTION pgsodium.create_key(pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamptz, text) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_decrypt(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key bytea, nonce bytea = NULL)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_decrypt'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_det_decrypt(bytea, bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_decrypt(bytea, bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_aead_det_decrypt(bytea, bytea, bigint, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_id bigint, context bytea = 'pgsodium', nonce bytea = NULL)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_decrypt_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_det_decrypt(bytea, bytea, bigint, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_det_decrypt(bytea, bytea, bigint, bytea, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_decrypt(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'aead-det';

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

ALTER FUNCTION            pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_decrypt(bytea, bytea, uuid, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'aead-det';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.decrypted_raw_key, nonce);
      END IF;

      RETURN pgsodium.crypto_aead_det_decrypt(message, additional, key.key_id, key.key_context, nonce);
    END
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION            pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid, bytea) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_decrypt(bytea, bytea, uuid, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_encrypt(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key bytea, nonce bytea = NULL)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_encrypt'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_det_encrypt(bytea, bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_det_encrypt(bytea, bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_aead_det_encrypt(bytea, bytea, bigint, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_id bigint, context bytea = 'pgsodium', nonce bytea = NULL)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_encrypt_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_det_encrypt(bytea, bytea, bigint, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_det_encrypt(bytea, bytea, bigint, bytea, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_encrypt(bytea, bytea, uuid, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea DEFAULT NULL)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'aead-det';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.decrypted_raw_key, nonce);
      END IF;

      RETURN pgsodium.crypto_aead_det_encrypt(message, additional, key.key_id, key.key_context, nonce);
    END
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION            pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_det_keygen()
 */
CREATE FUNCTION pgsodium.crypto_aead_det_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_det_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_det_keygen TO pgsodium_keymaker;

/*
 * crypto_aead_det_noncegen()
 */
CREATE FUNCTION pgsodium.crypto_aead_det_noncegen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_det_noncegen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_det_noncegen() TO pgsodium_keyiduser;

/*
 * crypto_aead_ietf_decrypt(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_decrypt'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_ietf_decrypt(bytea, bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_ietf_decrypt(bytea, bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_aead_ietf_decrypt(bytea, bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_decrypt_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    crypto_aead_ietf_decrypt(bytea, bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION crypto_aead_ietf_decrypt(bytea, bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_decrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'aead-ietf';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_aead_ietf_decrypt(message, additional, nonce, key.decrypted_raw_key);
      END IF;

      RETURN pgsodium.crypto_aead_ietf_decrypt(message, additional, nonce, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION            pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_encrypt'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_aead_ietf_encrypt(bytea, bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_encrypt_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_encrypt(message bytea, additional bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'aead-ietf';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_aead_ietf_encrypt(message, additional, nonce, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_aead_ietf_encrypt(message, additional, nonce, key.key_id, key.key_context);
    END;
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  STABLE
  SET search_path='';

ALTER FUNCTION            pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_aead_ietf_keygen()
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_keygen TO pgsodium_keymaker;

/*
 * crypto_aead_ietf_noncegen()
 */
CREATE FUNCTION pgsodium.crypto_aead_ietf_noncegen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_aead_ietf_noncegen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_aead_ietf_noncegen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_aead_ietf_noncegen TO pgsodium_keyiduser;

/*
 * crypto_auth(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth(message bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth(bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth(bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_auth(bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth(message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth(bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth(bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth(bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth(message bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'auth';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth(message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth(message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth(bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth(bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha256(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256(message bytea, secret bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256(bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bytea) TO pgsodium_keymaker;

/*
 * crypto_auth_hmacsha256(bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256(message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256(bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha256(bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256(message bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'hmacsha256';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth_hmacsha256(message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth_hmacsha256(message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth_hmacsha256(bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha256_keygen()
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256_keygen TO pgsodium_keymaker;

/*
 * crypto_auth_hmacsha256_verify(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256_verify(hash bytea, message bytea, secret bytea)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_verify'
  LANGUAGE C
  IMMUTABLE STRICT;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256_verify(hash bytea, message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha256_verify_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha256_verify(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha256_verify(signature bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'hmacsha256';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth_hmacsha256_verify(signature, message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth_hmacsha256_verify(signature, message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha512(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512(message bytea, secret bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512(bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_auth_hmacsha512(bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512(message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512(bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha512(bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512(message bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'hmacsha512';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth_hmacsha512(message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth_hmacsha512(message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth_hmacsha512(bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha512_keygen()
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_auth_hmacsha512_verify(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512_verify(hash bytea, message bytea, secret bytea)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_verify'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512_verify(hash bytea, message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_hmacsha512_verify_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth_hmacsha512_verify(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth_hmacsha512_verify(signature bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'hmacsha512';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth_hmacsha512_verify(signature, message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth_hmacsha512_verify(signature, message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_auth_keygen()
 */
CREATE FUNCTION pgsodium.crypto_auth_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_keygen TO pgsodium_keymaker;

/*
 * crypto_auth_verify(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_verify(mac bytea, message bytea, key bytea)
  RETURNS boolean
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_verify'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_verify(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_auth_verify(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_auth_verify(mac bytea, message bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS boolean
  AS '$libdir/pgsodium', 'pgsodium_crypto_auth_verify_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_verify(bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_auth_verify(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_auth_verify(mac bytea, message bytea, key_uuid uuid)
  RETURNS boolean AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'auth';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_auth_verify(mac, message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_auth_verify(mac, message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_auth_verify(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_auth_verify(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_box(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_box(message bytea, nonce bytea, public bytea, secret bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_box FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_box TO pgsodium_keyholder;

/*
 * crypto_box_new_keypair()
 */
CREATE FUNCTION pgsodium.crypto_box_new_keypair()
  RETURNS crypto_box_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_keypair'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_box_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_box_new_keypair TO pgsodium_keymaker;

/*
 * crypto_box_new_seed()
 */
CREATE FUNCTION pgsodium.crypto_box_new_seed()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_new_seed'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_box_noncegen()
 */
CREATE FUNCTION pgsodium.crypto_box_noncegen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_noncegen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_box_noncegen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_box_noncegen TO pgsodium_keymaker;

/*
 * crypto_box_open(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_box_open(ciphertext bytea, nonce bytea, public bytea, secret bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_open'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_box_open FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_box_open TO pgsodium_keyholder;

/*
 * crypto_box_seal(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_box_seal(message bytea, public_key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_seal'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_box_seal_open(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_box_seal_open(ciphertext bytea, public_key bytea, secret_key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_seal_open'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_box_seed_new_keypair(bytea)
 */
CREATE FUNCTION pgsodium.crypto_box_seed_new_keypair(seed bytea)
  RETURNS pgsodium.crypto_box_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_box_seed_keypair'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_box_seed_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_box_seed_new_keypair TO pgsodium_keymaker;

/*
 * crypto_cmp(text, text)
 */
CREATE FUNCTION pgsodium.crypto_cmp(text, text)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_cmp'
  LANGUAGE C
  IMMUTABLE
  STRICT;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_generichash(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_generichash(message bytea, key bytea DEFAULT NULL)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_generichash'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_generichash(bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_generichash(message bytea, key bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_generichash_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_generichash(bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_generichash(message bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'generichash';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_generichash(message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_generichash(message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_generichash(bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_generichash(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_generichash(bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_generichash_keygen()
 */
CREATE FUNCTION pgsodium.crypto_generichash_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_generichash_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_generichash_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_generichash_keygen TO pgsodium_keymaker;

/*
 * crypto_hash_sha256(bytea)
 */
CREATE FUNCTION pgsodium.crypto_hash_sha256(message bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_hash_sha256'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_hash_sha512(bytea)
 */
CREATE FUNCTION pgsodium.crypto_hash_sha512(message bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_hash_sha512'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_kdf_derive_from_key(bigint, bigint, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_kdf_derive_from_key(subkey_size bigint, subkey_id bigint, context bytea, primary_key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_derive_from_key'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_kdf_derive_from_key(bigint, bigint, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kdf_derive_from_key(bigint, bigint, bytea, bytea) TO pgsodium_keymaker;

/*
 * crypto_kdf_derive_from_key(integer, bigint, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_kdf_derive_from_key(subkey_size integer, subkey_id bigint, context bytea, primary_key uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = primary_key
        AND key_type = 'kdf';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_kdf_derive_from_key(subkey_size, subkey_id, context, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.derive_key(key.key_id, subkey_size, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STRICT STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_kdf_derive_from_key(integer, bigint, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_kdf_derive_from_key(integer, bigint, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kdf_derive_from_key(integer, bigint, bytea, uuid) TO pgsodium_keyiduser;


/*
 * crypto_kdf_keygen()
 */
CREATE FUNCTION pgsodium.crypto_kdf_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_kdf_keygen'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_kdf_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kdf_keygen TO pgsodium_keymaker;

/*
 * crypto_kx_client_session_keys(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_kx_client_session_keys(client_pk bytea, client_sk bytea, server_pk bytea)
  RETURNS crypto_kx_session
  AS '$libdir/pgsodium', 'pgsodium_crypto_kx_client_session_keys'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_kx_new_keypair()
 */
CREATE FUNCTION pgsodium.crypto_kx_new_keypair()
  RETURNS crypto_kx_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_kx_keypair'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_kx_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kx_new_keypair TO pgsodium_keymaker;

/*
 * crypto_kx_new_seed()
 */
CREATE FUNCTION pgsodium.crypto_kx_new_seed()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_kx_new_seed'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_kx_new_seed FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kx_new_seed TO pgsodium_keymaker;

/*
 * crypto_kx_seed_new_keypair(bytea)
 */
CREATE FUNCTION pgsodium.crypto_kx_seed_new_keypair(seed bytea)
  RETURNS crypto_kx_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_kx_seed_keypair'
  LANGUAGE C IMMUTABLE
  STRICT;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_kx_seed_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_kx_seed_new_keypair TO pgsodium_keymaker;

/*
 * crypto_kx_server_session_keys(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_kx_server_session_keys(server_pk bytea, server_sk bytea, client_pk bytea)
  RETURNS crypto_kx_session
  AS '$libdir/pgsodium', 'pgsodium_crypto_kx_server_session_keys'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_pwhash(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_pwhash(password bytea, salt bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_pwhash'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_pwhash_saltgen()
 */
CREATE FUNCTION pgsodium.crypto_pwhash_saltgen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_pwhash_saltgen'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_pwhash_str(bytea)
 */
CREATE FUNCTION pgsodium.crypto_pwhash_str(password bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_pwhash_str'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_pwhash_str_verify(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_pwhash_str_verify(hashed_password bytea, password bytea)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_pwhash_str_verify'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_secretbox(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_secretbox(message bytea, nonce bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox(bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_secretbox(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_secretbox(message bytea, nonce bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox_by_id'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox(bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox(bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_secretbox(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_secretbox(message bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'secretbox';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_secretbox(message, nonce, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_secretbox(message, nonce, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_secretbox(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_secretbox_keygen()
 */
CREATE FUNCTION pgsodium.crypto_secretbox_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox_keygen'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox_keygen TO pgsodium_keymaker;

/*
 * crypto_secretbox_noncegen()
 */
CREATE FUNCTION pgsodium.crypto_secretbox_noncegen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox_noncegen'
  LANGUAGE C VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox_noncegen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox_noncegen TO pgsodium_keyiduser;

/*
 * crypto_secretbox_open(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_secretbox_open(ciphertext bytea, nonce bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox_open'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox_open(bytea, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox_open(bytea, bytea, bytea) TO pgsodium_keyholder;

/*
 * crypto_secretbox_open(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_secretbox_open(message bytea, nonce bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretbox_open_by_id'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox_open(bytea, bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox_open(bytea, bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_secretbox_open(bytea, bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_secretbox_open(message bytea, nonce bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'secretbox';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_secretbox_open(message, nonce, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_secretbox_open(message, nonce, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_secretbox_open(bytea, bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_secretbox_open(bytea, bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_secretbox_open(bytea, bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_secretstream_keygen()
 */
CREATE FUNCTION pgsodium.crypto_secretstream_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_secretstream_xchacha20poly1305_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_shorthash(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_shorthash(message bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_shorthash'
  LANGUAGE C IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_shorthash(bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_shorthash(message bytea, key bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_shorthash_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_shorthash(bytea, bigint, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_shorthash(bytea, bigint, bytea) TO pgsodium_keyiduser;

/*
 * crypto_shorthash(bytea, uuid)
 */
CREATE FUNCTION pgsodium.crypto_shorthash(message bytea, key_uuid uuid)
  RETURNS bytea AS $$
    DECLARE
      key pgsodium.decrypted_key;
    BEGIN
      SELECT * INTO STRICT key
      FROM pgsodium.decrypted_key v
      WHERE id = key_uuid
        AND key_type = 'shorthash';

      IF key.decrypted_raw_key IS NOT NULL THEN
        RETURN pgsodium.crypto_shorthash(message, key.decrypted_raw_key);
      END IF;
      RETURN pgsodium.crypto_shorthash(message, key.key_id, key.key_context);
    END
  $$
  LANGUAGE plpgsql
  STRICT STABLE
  SECURITY DEFINER
  SET search_path = '';

ALTER FUNCTION            pgsodium.crypto_shorthash(bytea, uuid) OWNER TO pgsodium_keymaker;
REVOKE ALL ON FUNCTION    pgsodium.crypto_shorthash(bytea, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_shorthash(bytea, uuid) TO pgsodium_keyiduser;

/*
 * crypto_shorthash_keygen()
 */
CREATE FUNCTION pgsodium.crypto_shorthash_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_shorthash_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_shorthash_keygen FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_shorthash_keygen TO pgsodium_keymaker;

/*
 * crypto_sign(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign(message bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_sign_detached(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_detached(message bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_detached'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_sign_final_create(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_final_create(state bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_final_create'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_final_create FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_final_create TO pgsodium_keyholder;

/*
 * crypto_sign_final_verify(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_final_verify(state bytea, signature bytea, key bytea)
  RETURNS boolean
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_final_verify'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_final_verify FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_final_verify TO pgsodium_keyholder;

/*
 * crypto_sign_init()
 */
CREATE FUNCTION pgsodium.crypto_sign_init()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_init'
  LANGUAGE C
  IMMUTABLE
  STRICT;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_init FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_init TO pgsodium_keyholder;

/*
 * crypto_sign_new_keypair()
 */
CREATE FUNCTION pgsodium.crypto_sign_new_keypair()
  RETURNS crypto_sign_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_keypair'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_new_keypair TO pgsodium_keymaker;

/*
 * crypto_sign_new_seed()
 */
CREATE FUNCTION pgsodium.crypto_sign_new_seed()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_new_seed'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_sign_open(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_open(signed_message bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_open'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_sign_seed_new_keypair(bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_seed_new_keypair(seed bytea)
  RETURNS crypto_sign_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_seed_keypair'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_sign_update(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_update(state bytea, message bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_update'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_update FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_update TO pgsodium_keyholder;

/*
 * crypto_sign_update_agg1(bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_update_agg1(state bytea, message bytea)
  RETURNS bytea AS $$
    SELECT pgsodium.crypto_sign_update(
      COALESCE(state, pgsodium.crypto_sign_init()),
      message
    );
  $$
  LANGUAGE SQL
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_update_agg1 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_update_agg1 TO pgsodium_keyholder;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg1(bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea). This
initializes state if it has not already been initialized.';

/*
 * pgsodium.crypto_sign_update_agg2(cur_state bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_update_agg2(cur_state bytea,
                 initial_state bytea,
                 message bytea)
  RETURNS bytea
  AS $$
    SELECT pgsodium.crypto_sign_update(
      COALESCE(cur_state, initial_state),
      message
    )
  $$
  LANGUAGE SQL
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_sign_update_agg2 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_update_agg2 TO pgsodium_keyholder;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg2(bytea, bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea, bytea). This
initializes state to the state passed to the aggregate as a parameter,
if it has not already been initialized.';

CREATE AGGREGATE pgsodium.crypto_sign_update_agg(message bytea)
(
  SFUNC = pgsodium.crypto_sign_update_agg1,
  STYPE = bytea,
  PARALLEL = unsafe
);

COMMENT ON AGGREGATE pgsodium.crypto_sign_update_agg(bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';

CREATE AGGREGATE pgsodium.crypto_sign_update_agg(state bytea, message bytea)
(
  SFUNC = pgsodium.crypto_sign_update_agg2,
  STYPE = bytea,
  PARALLEL = unsafe
);

COMMENT ON AGGREGATE pgsodium.crypto_sign_update_agg(bytea, bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

The first argument to this aggregate is the input state. This may be
the result of a previous crypto_sign_update_agg(), a previous
crypto_sign_update().

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';

/*
 * crypto_sign_verify_detached(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_sign_verify_detached(sig bytea, message bytea, key bytea)
  RETURNS boolean
  AS '$libdir/pgsodium', 'pgsodium_crypto_sign_verify_detached'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_signcrypt_new_keypair()
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_new_keypair()
  RETURNS pgsodium.crypto_signcrypt_keypair
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_keypair'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_new_keypair FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_new_keypair TO pgsodium_keymaker;

/*
 * crypto_signcrypt_sign_after(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_sign_after(state bytea, sender_sk bytea, ciphertext bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_sign_after'
  LANGUAGE C;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_sign_after FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_sign_after TO pgsodium_keyholder;

/*
 * crypto_signcrypt_sign_before(bytea, bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_sign_before(sender bytea, recipient bytea, sender_sk bytea, recipient_pk bytea, additional bytea)
  RETURNS crypto_signcrypt_state_key
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_sign_before'
  LANGUAGE C;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_sign_before FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_sign_before TO pgsodium_keyholder;

/*
 * crypto_signcrypt_verify_after(bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_verify_after(state bytea, signature bytea, sender_pk bytea, ciphertext bytea)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_verify_after'
  LANGUAGE C;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_verify_after FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_verify_after TO pgsodium_keyholder;

/*
 * crypto_signcrypt_verify_before(bytea, bytea, bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_verify_before(signature bytea, sender bytea, recipient bytea, additional bytea, sender_pk bytea, recipient_sk bytea)
  RETURNS pgsodium.crypto_signcrypt_state_key
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_verify_before'
  LANGUAGE C;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_verify_before FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_verify_before TO pgsodium_keyholder;

/*
 * crypto_signcrypt_verify_public(bytea, bytea, bytea, bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_signcrypt_verify_public(signature bytea, sender bytea, recipient bytea, additional bytea, sender_pk bytea, ciphertext bytea)
  RETURNS bool
  AS '$libdir/pgsodium', 'pgsodium_crypto_signcrypt_verify_public'
  LANGUAGE C;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.crypto_signcrypt_verify_public FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_signcrypt_verify_public TO pgsodium_keyholder;

/*
 * crypto_stream_xchacha20(bigint, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20(bigint, bytea, bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20(bigint, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20(bigint, bytea, bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_keygen()
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_keygen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_noncegen()
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_noncegen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_noncegen'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_xor(bytea, bytea, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_xor(bytea, bytea, bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_xor(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_xor(bytea, bytea, bigint, context bytea = 'pgosdium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_ic'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bigint, bytea)
 */
CREATE FUNCTION pgsodium.crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_stream_xchacha20_xor_ic_by_id'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * derive_key(bigint, integer, bytea)
 */
CREATE FUNCTION pgsodium.derive_key(key_id bigint, key_len integer = 32, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_derive'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.derive_key FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.derive_key TO pgsodium_keymaker;

/*
 * disable_security_label_trigger()
 */
CREATE FUNCTION pgsodium.disable_security_label_trigger()
  RETURNS void AS $$
    ALTER EVENT TRIGGER pgsodium_tg_tce_update DISABLE;
  $$
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * enable_security_label_trigger()
 */
CREATE FUNCTION pgsodium.enable_security_label_trigger()
  RETURNS void AS $$
    ALTER EVENT TRIGGER pgsodium_tg_tce_update ENABLE;
  $$
  LANGUAGE sql
  SECURITY DEFINER
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * get_key_by_id(uuid)
 */
CREATE FUNCTION pgsodium.get_key_by_id(uuid)
  RETURNS pgsodium.valid_key AS $$
    SELECT * FROM pgsodium.valid_key WHERE id = $1;
  $$
  SECURITY DEFINER
  LANGUAGE sql
  SET search_path = '';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * get_key_by_name(text)
 */
CREATE FUNCTION pgsodium.get_key_by_name(text)
  RETURNS pgsodium.valid_key AS $$
      SELECT * from pgsodium.valid_key WHERE name = $1;
  $$
  SECURITY DEFINER
  LANGUAGE sql
  SET search_path = '';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * get_named_keys(text)
 */
CREATE FUNCTION pgsodium.get_named_keys(filter text='%')
  RETURNS SETOF pgsodium.valid_key
  AS $$
      SELECT * from pgsodium.valid_key vk WHERE vk.name ILIKE filter;
  $$
  SECURITY DEFINER
  LANGUAGE sql
  SET search_path = '';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * has_mask(regrole, text)
 * FIXME: matching on 'ACCESS%<tablename>%' could match other table where
 *        <tablename> is a sub-string
 */
CREATE FUNCTION pgsodium.has_mask(role regrole, source_name text)
  RETURNS boolean AS $$
    SELECT EXISTS(
      SELECT 1
        FROM pg_catalog.pg_shseclabel
       WHERE  objoid = role
         AND provider = 'pgsodium'
         AND label ilike 'ACCESS%' || source_name || '%')
  $$
  SET search_path='pg_catalog'
  LANGUAGE sql;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * mask_role(regrole, text, text)
 * WARNING: view_name is supposed to be schema qualified and properly quoted.
 */
CREATE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS $$
    DECLARE
      body text;
    BEGIN
      body = pg_catalog.format(
        'GRANT SELECT ON pgsodium.key TO %I;
         GRANT pgsodium_keyiduser TO %1$I;
         GRANT ALL ON %s TO %1$I',
        masked_role,
        view_name -- this one is supposed to be already quoted correctly.
      );

      IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
        RAISE NOTICE '%', body;
      END IF;

      EXECUTE body;
      RETURN;
    END
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * pgsodium_derive(bigint, integer, bytea
 */
CREATE FUNCTION pgsodium.pgsodium_derive(key_id bigint, key_len integer = 32, context bytea = decode('pgsodium', 'escape'))
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_derive'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.pgsodium_derive FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.pgsodium_derive TO pgsodium_keymaker;

/*
 * quote_assoc(text, boolean)
 */
CREATE FUNCTION pgsodium.quote_assoc(text, boolean = false)
  RETURNS text
  AS $$
      WITH a AS (SELECT array_agg(CASE WHEN $2 THEN
                                      'new.' || quote_ident(trim(v))
                                  ELSE quote_ident(trim(v)) END) as r
                 FROM regexp_split_to_table($1, '\s*,\s*') as v)
      SELECT array_to_string(a.r, '::text || ') || '::text' FROM a;
  $$
  LANGUAGE sql;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * randombytes_buf(integer)
 */
CREATE FUNCTION pgsodium.randombytes_buf(size integer)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_randombytes_buf'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.randombytes_buf FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.randombytes_buf TO pgsodium_keyiduser;

/*
 * randombytes_buf_deterministic(integer, bytea)
 */
CREATE FUNCTION pgsodium.randombytes_buf_deterministic(size integer, seed bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_randombytes_buf_deterministic'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.randombytes_buf_deterministic FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.randombytes_buf_deterministic TO pgsodium_keyiduser;

/*
 * randombytes_new_seed()
 */
CREATE FUNCTION pgsodium.randombytes_new_seed()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_randombytes_new_seed'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.randombytes_new_seed FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.randombytes_new_seed TO pgsodium_keymaker;

/*
 * randombytes_random()
 */
CREATE FUNCTION pgsodium.randombytes_random()
  RETURNS integer
  AS '$libdir/pgsodium', 'pgsodium_randombytes_random'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.randombytes_random FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.randombytes_random TO pgsodium_keyiduser;

/*
 * randombytes_uniform(integer)
 */
CREATE FUNCTION pgsodium.randombytes_uniform(upper_bound integer)
  RETURNS integer
  AS '$libdir/pgsodium', 'pgsodium_randombytes_uniform'
  LANGUAGE C
  VOLATILE;

-- FIXME: owner?
REVOKE ALL ON FUNCTION    pgsodium.randombytes_uniform FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgsodium.randombytes_uniform TO pgsodium_keyiduser;

/*
 * sodium_base642bin(text)
 */
CREATE FUNCTION pgsodium.sodium_base642bin(base64 text) RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_sodium_base642bin'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * sodium_bin2base64(bytea)
 */
CREATE FUNCTION pgsodium.sodium_bin2base64(bin bytea) RETURNS text
  AS '$libdir/pgsodium', 'pgsodium_sodium_bin2base64'
  LANGUAGE C
  IMMUTABLE;

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

/*
 * version()
 */
CREATE FUNCTION pgsodium.version()
  RETURNS text AS $$
    SELECT extversion
    FROM pg_catalog.pg_extension
    WHERE extname = 'pgsodium'
  $$
  LANGUAGE sql
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

CREATE FUNCTION pgsodium.tce_decrypt_col(
    message bytea,
    keyid uuid,
    nonce bytea DEFAULT NULL,
    ad text DEFAULT '')
  RETURNS bytea AS $$
    BEGIN
      IF message IS NULL OR keyid IS NULL THEN
        RETURN NULL;
      END IF;

      RETURN pgsodium.crypto_aead_det_decrypt(
        message,
        pg_catalog.convert_to(ad, 'utf8'),
        keyid,
        nonce
      );
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

CREATE FUNCTION pgsodium.tce_decrypt_col(
    message text,
    keyid uuid,
    nonce bytea DEFAULT NULL,
    ad text DEFAULT '')
  RETURNS text AS $tce_decrypt_col$
    BEGIN
      IF message IS NULL OR keyid IS NULL THEN
        RETURN NULL;
      END IF;

      RETURN pg_catalog.convert_from(
        pgsodium.crypto_aead_det_decrypt(
          pg_catalog.decode(message, 'base64'),
          pg_catalog.convert_to(ad, 'utf8'),
          keyid,
          nonce
        ), 'utf8' -- FIXME: this should use the column encoding?
      );
    END
  $tce_decrypt_col$
  LANGUAGE plpgsql
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

CREATE OR REPLACE FUNCTION pgsodium.tce_update_views()
  RETURNS void AS $$
    SELECT pgsodium.tce_update_view(objoid)
      FROM pg_catalog.pg_seclabel sl
      JOIN pg_catalog.pg_class cl ON (cl.oid = sl.objoid)
      WHERE sl.label ILIKE 'ENCRYPT%'
        AND sl.provider = 'pgsodium'
        AND cl.relowner = session_user::regrole::oid
        AND sl.objoid::regclass != 'pgsodium.key'::regclass;
  $$
  LANGUAGE SQL
  SET search_path='';

-- FIXME: owner?
-- FIXME: revoke?
-- FIXME: grant?

--==============================================================================
--                               PRIVILEGES
--==============================================================================

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

-- pgsodium_keyiduser can use all tables and sequences (functions are granted individually)
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON TABLES FROM pgsodium_keyiduser;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON SEQUENCES FROM pgsodium_keyiduser;

ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON TABLES TO pgsodium_keyholder;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium GRANT ALL ON SEQUENCES TO pgsodium_keyholder;

REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM pgsodium_keyiduser;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM pgsodium_keyiduser;

GRANT ALL ON ALL TABLES IN SCHEMA pgsodium TO pgsodium_keymaker;
GRANT ALL ON ALL SEQUENCES IN SCHEMA pgsodium TO pgsodium_keymaker;

--==============================================================================
--                             MAINTENANCES
--==============================================================================


SECURITY LABEL FOR pgsodium ON COLUMN pgsodium.key.raw_key
  IS 'ENCRYPT WITH KEY COLUMN parent_key ASSOCIATED (id, associated_data) NONCE raw_key_nonce';

-- TT SELECT * FROM pgsodium.update_mask('pgsodium.key'::regclass::oid);

-- FIXME: why revoke not generated ?
-- FIXME: why grant not generated ?

SELECT pgsodium.tce_update_attr_tg(a.attrelid, a.attnum)
FROM pg_catalog.pg_attribute a
WHERE a.attrelid = 'pgsodium.key'::regclass
  AND a.attname = 'raw_key';

GRANT SELECT ON pgsodium.decrypted_key TO pgsodium_keymaker;
