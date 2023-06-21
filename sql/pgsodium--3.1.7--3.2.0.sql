/*
 * change: replaced in 3.0.5 with "create_mask_view(oid, integer, boolean)".
 */
DROP FUNCTION IF EXISTS pgsodium.create_mask_view(oid, boolean);

/*
 * change: replaced in 3.0.5 by the "pgsodium.mask_columns" view.
 */
DROP FUNCTION IF EXISTS pgsodium.mask_columns(oid);

/*
 * change: schema "pgsodium_masks" removed in 3.0.4
 * FIXME: how the extension handle bw compatibility when a table having a view
 *        in pgsodium_masks is update or has a seclabel added/changed? A new
 *        view is created outside of pgsodium_masks? What about the client app
 *        and the old view?
 */
DROP SCHEMA IF EXISTS pgsodium_masks;

/*
 * changes:
 * - read debug GUC from settings.
 * - either (re)create the trigger if the event apply on a column or
 *   recreate the view if the event apply on a table.
 */
CREATE OR REPLACE FUNCTION pgsodium.trg_mask_update()
RETURNS EVENT_TRIGGER
AS $$
DECLARE
  r record;
  debug bool := CASE WHEN count(1) > 0
                THEN pg_catalog.current_setting('pgsodium.debug', false)::bool
                ELSE false::bool
                END
                FROM pg_catalog.pg_settings WHERE name ~ 'pgsodium.debug';
BEGIN
  IF (select bool_or(in_extension) FROM pg_event_trigger_ddl_commands()) THEN
    RAISE NOTICE 'skipping pgsodium mask regeneration in extension';
	RETURN;
  END IF;

  /*
   * Loop on each event to either rebuilt the view or setup column
   * encryption.
   */
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
    IF debug
    THEN
      RAISE NOTICE 'trg_mask_update: classid: %, objid: %, objsubid: %, tag: %, obj_type: %, schema: %, identity: %, in_ext: %',
        r.classid, r.objid, r.objsubid, r.command_tag, r.object_type,
        r.schema_name, r.object_identity, r.in_extension;
    END IF;

    IF r.object_type = 'table column' AND r.objsubid <> 0
    THEN
      /*
       * Create/update encryption trigger for given attribute. This triggers
       * the creation/update of the related decrypting view as well.
       */
      PERFORM pgsodium.create_mask_column(r.objid, r.objsubid, debug);
    ELSIF r.object_type = 'table' AND r.objsubid = 0
    THEN
      /*
       * Create/update the view on given table
       */
       PERFORM pgsodium.create_mask_view(r.objid, debug);
    END IF;
  END LOOP;
END
$$
LANGUAGE plpgsql
SET search_path='';


/*
 * change: create_mask_view(oid,integer,boolean) replaced by a new version
 *         of create_mask_view(oid,boolean)
 */
DROP FUNCTION pgsodium.create_mask_view(oid,integer,boolean);

/*
 * change: droped from 3.2.0
 */
DROP FUNCTION pgsodium.encrypted_columns(oid);
DROP FUNCTION pgsodium.encrypted_column(oid, record);

/*
 * change: add nspname column to pgsodium.masking_rule. We need to DROP the
 *         view and mask_columns as it depends on it.
 */
DROP VIEW pgsodium.mask_columns;
DROP VIEW pgsodium.masking_rule;

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
      n.nspname,
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
           JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid AND sl.objoid = c.oid
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
LEFT JOIN pgsodium.masking_rule m ON m.attrelid = a.attrelid
                                 AND m.attname = a.attname
WHERE  a.attnum > 0 -- exclude ctid, cmin, cmax
  AND  NOT a.attisdropped
ORDER BY a.attnum;


/*
 * new: common trigger to encrypt any column using a key column
 */
CREATE FUNCTION pgsodium.trg_encrypt_using_key_col()
RETURNS trigger
AS '$libdir/pgsodium'
LANGUAGE C
SECURITY DEFINER;


/*
 * new: common trigger to encrypt any column using a key id
 */
CREATE FUNCTION pgsodium.trg_encrypt_using_key_id()
RETURNS trigger
AS '$libdir/pgsodium'
LANGUAGE C
SECURITY DEFINER;

/*
 * new: new version of create_mask_view(oid,boolean). Only creates or replace
 *      decrypting view. Doesn't generate trigger anymore, exits when no
 *      encrypted cols found.
 */
CREATE FUNCTION pgsodium.create_mask_view(relid oid, debug bool)
RETURNS void
AS $$
DECLARE
  m record;
  body text;
  source_name text;
  view_owner regrole = session_user;
  rule pgsodium.masking_rule;
  privs aclitem[];
  priv record;
BEGIN
  SELECT * INTO rule
  FROM pgsodium.masking_rule AS mr
  WHERE mr.attrelid = create_mask_view.relid
  LIMIT 1;

  IF rule.view_name IS NULL
  THEN
    RAISE NOTICE 'skip decrypting view: relation % has no encrypted columns', relid::regclass;
    RETURN;
  END IF;

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
    REVOKE ALL ON %1$s FROM public;
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

  raise notice 'about to masking role % %', source_name, rule.view_name;
  PERFORM pgsodium.mask_role(oid::regrole, source_name, rule.view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
LANGUAGE plpgsql
VOLATILE
SET search_path='pg_catalog';

/*
 * change: fix call to new create_mask_view()
 */
CREATE OR REPLACE FUNCTION pgsodium.update_mask(target oid, debug boolean = false)
RETURNS void
AS $$
BEGIN
  PERFORM pgsodium.disable_security_label_trigger();
  PERFORM pgsodium.create_mask_view(objoid, debug)
    FROM pg_catalog.pg_seclabel sl
    WHERE sl.objoid = target
      AND sl.label ILIKE 'ENCRYPT%'
      AND sl.provider = 'pgsodium';
  PERFORM pgsodium.enable_security_label_trigger();
  RETURN;
END
$$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path='';

/*
 * new: this function creates encryption trigger for given column
 */
CREATE FUNCTION pgsodium.create_mask_column(relid oid, attnum integer, debug bool)
RETURNS void
AS $$
DECLARE
  body text;
  m pgsodium.masking_rule;
  tgname text;
  tgf text;
  tgargs text;
  attname text;
BEGIN
  -- get encryption rules for given field
  SELECT * INTO STRICT m
  FROM pgsodium.masking_rule AS mr
  WHERE mr.attrelid = relid
    AND mr.attnum = create_mask_column.attnum;

  tgname = m.relname || '_encrypt_secret_trigger_' || m.attname;
  tgargs = pg_catalog.quote_literal(m.attname); -- FIXME: test?

  IF m.key_id_column IS NOT NULL
  THEN
    tgf = 'trg_encrypt_using_key_col';
    tgargs = pg_catalog.format('%s, %L', tgargs, m.key_id_column);
  ELSIF m.key_id IS NOT NULL
  THEN
    tgf = 'trg_encrypt_using_key_id';
    tgargs = pg_catalog.format('%s, %L', tgargs, m.key_id);
  ELSE
      -- FIXME trigger set col to NULL
  END IF;

  IF m.nonce_column IS NOT NULL
  THEN tgargs = pg_catalog.format('%s, %L', tgargs, m.nonce_column);
  END IF;

  IF m.associated_columns IS NOT NULL
  THEN
    IF m.nonce_column IS NULL
    THEN
      /*
       * empty nonce is required because associated cols starts at
       * the 4th argument.
       */
      tgargs = pg_catalog.format('%s, %L', tgargs, '');
    END IF;

    FOR attname IN
        SELECT pg_catalog.regexp_split_to_table(m.associated_columns,
                                                '\s*,\s*')
    LOOP
        tgargs = pg_catalog.format('%s, %L', tgargs, attname);
    END LOOP;
  END IF;

  body = format(
    $c$
      DROP TRIGGER IF EXISTS %1$I ON %3$I.%4$I;

      CREATE TRIGGER %1$I BEFORE INSERT OR UPDATE OF %2$I
        ON %3$I.%4$I FOR EACH ROW EXECUTE FUNCTION
        pgsodium.%5$I(%6$s);
    $c$,
    tgname,    -- 1
    m.attname, -- 2
    m.nspname, -- 3
    m.relname, -- 4
    tgf,       -- 5
    tgargs     -- 6
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  -- update related view
  PERFORM pgsodium.create_mask_view(relid, debug);

  RETURN;
END
$$
LANGUAGE plpgsql
SET search_path='';

/*
 * change: constraint names generated by the create table pgsodium.key in
 *         pgsodium--3.2.0.sql are different from the older ones.
 */
ALTER TABLE pgsodium.key RENAME CONSTRAINT "pgsodium_raw" TO "key_check";
ALTER INDEX pgsodium.pgsodium_key_unique_name RENAME TO key_name_key;

/*
 * change: replace old triggers
 */
DO $$
DECLARE rs record;
BEGIN
  FOR rs IN
    SELECT r.oid AS reloid, r.relname, rn.nspname AS relnsp,
           t.tgname,
           tn.nspname AS pronsp, tp.proname,
           a.attnum, a.attname
    FROM pg_catalog.pg_depend d
    JOIN pg_catalog.pg_trigger t ON d.objid = t.oid
    JOIN pg_catalog.pg_class r ON t.tgrelid = r.oid
    JOIN pg_catalog.pg_namespace rn ON r.relnamespace = rn.oid
    JOIN pg_catalog.pg_proc tp ON t.tgfoid = tp.oid
    JOIN pg_catalog.pg_namespace tn ON tp.pronamespace = tn.oid
    JOIN pg_catalog.pg_attribute a ON d.refobjsubid = a.attnum   AND d.refobjid = a.attrelid
    JOIN pg_catalog.pg_seclabel l  ON d.refobjsubid = l.objsubid AND d.refobjid = l.objoid
    WHERE classid = 'pg_trigger'::regclass
      AND l.provider = 'pgsodium'
      AND l.label ILIKE 'ENCRYPT %'
      AND t.tgname ~ '_encrypt_secret_trigger_'
      AND tp.proname ~ '_encrypt_secret_'
      AND tp.prorettype = 'trigger'::regtype
    LOOP
      -- DROP them all
      RAISE NOTICE 'DROP TRIGGER/FUNCTION %.%.%/%.%',
        rs.relnsp, rs.relname, rs.tgname, rs.pronsp, rs.proname;
      EXECUTE format('DROP TRIGGER %I ON %I.%I', rs.tgname, rs.relnsp, rs.relname);
      EXECUTE format('DROP FUNCTION %I.%I', rs.pronsp, rs.proname);
      -- create them
      PERFORM pgsodium.create_mask_column(rs.reloid, rs.attnum, true);
    END LOOP;
  END
$$;

/*
 * change: force regenerating the decrypted_key view to add the missing column
 *         "user_data" to the view.
 */
SELECT * FROM pgsodium.update_mask('pgsodium.key'::regclass::oid);

/*
 * Fix privileges
 */

REVOKE ALL ON pgsodium.key FROM pgsodium_keyiduser;

REVOKE ALL ON pgsodium.key FROM pgsodium_keymaker;
GRANT SELECT, INSERT, UPDATE, DELETE ON pgsodium.key TO pgsodium_keymaker;
REVOKE ALL ON pgsodium.decrypted_key FROM pgsodium_keymaker;
GRANT SELECT, INSERT, UPDATE, DELETE ON pgsodium.decrypted_key TO pgsodium_keymaker;

REVOKE ALL ON pgsodium.decrypted_key FROM pgsodium_keyholder;
GRANT SELECT, INSERT, UPDATE, DELETE ON pgsodium.decrypted_key TO pgsodium_keyholder;

ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON TABLES FROM pgsodium_keyholder;
ALTER DEFAULT PRIVILEGES IN SCHEMA pgsodium REVOKE ALL ON SEQUENCES FROM pgsodium_keyholder;
