/*
 * change: replaced in 3.0.5 with "create_mask_view(oid, integer, boolean)".
 */
DROP FUNCTION IF EXISTS pgsodium.create_mask_view(oid, boolean);

/*
 * change: replaced in 3.0.5 by the "pgsodium.mask_columns" view.
 */
DROP FUNCTION IF EXISTS pgsodium.mask_columns(oid);

/*
 * change: useless code since 3.1.1 and the introduction of encrypted_column(oid)
 */
DROP FUNCTION IF EXISTS pgsodium.encrypted_columns(oid);

/*
 * change: useless code since 3.2.0
 */
DROP FUNCTION IF EXISTS pgsodium.encrypted_column(oid, record);

/*
 * change: useless code since 3.2.0
 */
DROP FUNCTION IF EXISTS pgsodium.decrypted_columns(oid);

/*
 * change: useless code since 3.2.0
 */
DROP FUNCTION IF EXISTS pgsodium.create_mask_view(oid, integer, boolean);

/*
 * change: replaced by tce_update_views
 */
DROP FUNCTION IF EXISTS pgsodium.update_masks(boolean);


/*
 * change:
 *   redundant with
 *   pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid, bytea DEFAULT NULL);
 */
DROP FUNCTION pgsodium.crypto_aead_det_encrypt(bytea, bytea, uuid);

/*
 * change: useless code since 3.2.0
 */
DROP VIEW IF EXISTS pgsodium.mask_columns;

/*
 * change: schema "pgsodium_masks" removed in 3.0.4
 * FIXME: how the extension handle bw compatibility when a table having a view
 *        in pgsodium_masks is update or has a seclabel added/changed? A new
 *        view is created outside of pgsodium_masks? What about the client app
 *        and the old view?
 */
DROP SCHEMA IF EXISTS pgsodium_masks;

/*
 * change: replaced with "tg_tce_update()"
 */
DROP FUNCTION pgsodium.trg_mask_update();

/*
 * change: created in 3.2.0
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

        /*
         * Create/update encryption trigger for given field. This triggers
         * the creation/update of the related decrypting view as well.
         */
        PERFORM pgsodium.tce_update_tg(r.objid, r.objsubid);
      END LOOP;
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

/*
 * change: created in 3.2.0
 */
CREATE FUNCTION pgsodium.tce_update_attr_tg(relid oid, attnum integer)
  RETURNS void AS $tce_update_tg$
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
        AND mr.attnum = tce_update_tg.attnum;

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
        tgname,            -- 1
        rule.attname,      -- 2
        rule.relnamespace, -- 3
        rule.relname,      -- 4
        tgf,               -- 5
        tgargs             -- 6
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
  $tce_update_tg$
  LANGUAGE plpgsql
  SET search_path='';

/*
 * change: created in 3.2.0
 */
CREATE FUNCTION pgsodium.tce_update_view(relid oid)
  RETURNS void AS $tce_update_view$
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

      IF viewname IS NULL THEN
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
        REVOKE ALL ON %1$s FROM public;
        ',
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
        body = format(
          'GRANT %s ON %s TO %I',
          r.privilege_type,
          viewname, -- supposed to be already escaped
          r.grantee::regrole::text
        );

        IF pg_catalog.current_setting('pgsodium.debug')::bool THEN
          RAISE NOTICE '%', body;
        END IF;

        EXECUTE body;
      END LOOP;

      PERFORM pgsodium.mask_role(oid::regrole, origrelpath, rule.view_name)
      FROM pg_catalog.pg_roles
      WHERE pgsodium.has_mask(oid::regrole, origrelpath);
    END
  $tce_update_view$
  LANGUAGE plpgsql
  SET search_path='';

/*
 * change: created in 3.2.0
 */
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

/*
 * change: remove useless "mask_schema" and "source_schema" variables
 * change: support debug
 */
CREATE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS $$
    DECLARE
      body text;
    BEGIN
      body = format('
        GRANT SELECT ON pgsodium.key TO %I;
        GRANT pgsodium_keyiduser TO %1$I;
        GRANT ALL ON %I TO %1$I;',
        masked_role, view_name);

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

/*
 * change: schema-qualify "pg_shseclabel" + search_path.
 */
CREATE OR REPLACE FUNCTION pgsodium.has_mask(role regrole, source_name text)
  RETURNS boolean AS $$
    SELECT EXISTS(
      SELECT 1
        FROM pg_catalog.pg_shseclabel
       WHERE objoid = role
         AND provider = 'pgsodium'
         AND label ILIKE 'ACCESS%' || source_name || '%')
  $$
  LANGUAGE sql
  SET search_path='pg_catalog';

CREATE OR REPLACE FUNCTION pgsodium.tce_decrypt_col(
    message bytea,
    keyid uuid,
    nonce bytea DEFAULT NULL,
    ad text DEFAULT '')
  RETURNS bytea AS $$
    DECLARE
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

CREATE OR REPLACE FUNCTION pgsodium.tce_decrypt_col(
    message text,
    keyid uuid,
    nonce bytea DEFAULT NULL,
    ad text DEFAULT '')
  RETURNS text AS $tce_decrypt_col$
    DECLARE
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

/*
 * change: makes "nonce" argument "DEFAULT NULL"
 */
CREATE OR REPLACE FUNCTION pgsodium.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea DEFAULT NULL)
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
 * change: add some comments
 */
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

DROP EVENT TRIGGER pgsodium_trg_mask_update;
CREATE EVENT TRIGGER pgsodium_tg_tce_update
  ON ddl_command_end
  WHEN TAG IN (
    'SECURITY LABEL',
    'ALTER TABLE'
  )
  EXECUTE PROCEDURE pgsodium.tg_tce_update();
