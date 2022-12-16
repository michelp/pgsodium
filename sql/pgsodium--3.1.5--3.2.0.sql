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
 * change: schema "pgsodium_masks" removed in 3.0.4
 * FIXME: how the extension handle bw compatibility when a table having a view
 *        in pgsodium_masks is update or has a seclabel added/changed? A new
 *        view is created outside of pgsodium_masks? What about the client app
 *        and the old view?
 */
DROP SCHEMA IF EXISTS pgsodium_masks;

/*
 * change: remove useless "r" variable
 */
CREATE OR REPLACE FUNCTION pgsodium.trg_mask_update()
  RETURNS EVENT_TRIGGER
  AS $$
    BEGIN
      -- FIXME: should we filter out all extensions BUT pgsodium?
      --        This would allow the extension to generate the decrypted_key
      --        view when creating the security label without explicitly call
      --        "update_masks()" at the end of this script.
      IF ( SELECT bool_or(in_extension) FROM pg_event_trigger_ddl_commands() )
      THEN
        RAISE NOTICE 'skipping pgsodium mask regeneration in extension';
        RETURN;
      END IF;
      PERFORM pgsodium.update_masks();
    END
  $$
  LANGUAGE plpgsql
  SET search_path='';

/*
 * change: remove useless "mask_schema" variable
 */
CREATE OR REPLACE FUNCTION pgsodium.mask_role(masked_role regrole, source_name text, view_name text)
  RETURNS void AS $$
  DECLARE
      source_schema REGNAMESPACE = (regexp_split_to_array(source_name, '\.'))[1];
    BEGIN
      EXECUTE format(
        'GRANT SELECT ON pgsodium.key TO %s',
        masked_role);

      EXECUTE format(
        'GRANT pgsodium_keyiduser TO %s',
        masked_role);

      EXECUTE format(
        'GRANT ALL ON %s TO %s',
        view_name,
        masked_role);
      RETURN;
    END
  $$
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path='pg_catalog';

/*
 * change: remove useless "comma" and "expression" variables
 */
CREATE OR REPLACE FUNCTION pgsodium.encrypted_column(relid OID, m record)
  RETURNS TEXT AS $$
    BEGIN
      IF m.format_type = 'text' THEN
          RETURN format(
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
          RETURN format(
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
      RAISE 'Not supported type % for encryoted column %',
        m.format_type, m.attname;
    END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='';

/*
 * change: keep user privs on regenerated views. (#58)
 */
CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false)
  RETURNS void AS $$
    DECLARE
      m record;
      body text;
      source_name text;
      view_owner regrole = session_user;
      rule pgsodium.masking_rule;
      privs aclitem[];
      priv record;
    BEGIN
      SELECT DISTINCT * INTO STRICT rule
      FROM pgsodium.masking_rule
      WHERE attrelid = relid
        AND attnum = subid;

      source_name := relid::regclass::text;

      BEGIN
        SELECT relacl INTO STRICT privs
        FROM pg_catalog.pg_class
        WHERE oid = rule.view_name::regclass::oid;
      EXCEPTION
        WHEN undefined_table THEN
          SELECT relacl INTO STRICT privs FROM pg_catalog.pg_class WHERE oid = relid;
      END;

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

      FOR priv IN SELECT * FROM pg_catalog.aclexplode(privs) LOOP
        body = format(
          'GRANT %s ON %s TO %s',
          priv.privilege_type,
          rule.view_name,
          priv.grantee::regrole::text
        );

        IF debug THEN
          RAISE NOTICE '%', body;
        END IF;

        EXECUTE body;
      END LOOP;

      FOR m IN
        SELECT *
        FROM pgsodium.mask_columns
        WHERE attrelid = relid
      LOOP
        IF m.key_id IS NULL AND m.key_id_column IS NULL THEN
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

          IF debug THEN
            RAISE NOTICE '%', body;
          END IF;

          EXECUTE body;

        END IF;
      END LOOP;

      PERFORM pgsodium.mask_role(oid::regrole, source_name, rule.view_name)
      FROM pg_catalog.pg_roles
      WHERE pgsodium.has_mask(oid::regrole, source_name);

      RETURN;
    END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='';
