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
BEGIN
  -- get encryption rules for given field
  SELECT * INTO STRICT m
  FROM pgsodium.masking_rule AS mr
  WHERE mr.attrelid = relid
    AND mr.attnum = create_mask_column.attnum;

  IF m.key_id IS NULL AND m.key_id_column IS NULL
  THEN
    RETURN;
  END IF;

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
    m.relnamespace,
    m.relname,
    m.attname,
    pgsodium.encrypted_column(relid, m),
    session_user,
    relid::regclass::text
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
