CREATE OR REPLACE FUNCTION pgsodium.crypto_sign_update_agg1(state bytea, message bytea)
 RETURNS bytea
AS
$$
 SELECT pgsodium.crypto_sign_update(COALESCE(state, pgsodium.crypto_sign_init()), message);
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg1(bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea). This
initializes state if it has not already been initialized.';

CREATE OR REPLACE FUNCTION pgsodium.crypto_sign_update_agg2(cur_state bytea,
                 initial_state bytea,
				 message bytea)
 RETURNS bytea
as
$$
 SELECT pgsodium.crypto_sign_update(
       COALESCE(cur_state, initial_state),
	   message)
$$
LANGUAGE SQL IMMUTABLE;

COMMENT ON FUNCTION pgsodium.crypto_sign_update_agg2(bytea, bytea, bytea) IS
'Internal helper function for crypto_sign_update_agg(bytea, bytea). This
initializes state to the state passed to the aggregate as a parameter,
if it has not already been initialized.';

CREATE OR REPLACE AGGREGATE pgsodium.crypto_sign_update_agg(message bytea)
 (
  SFUNC = pgsodium.crypto_sign_update_agg1,
  STYPE = bytea,
  PARALLEL = unsafe);

COMMENT ON AGGREGATE pgsodium.crypto_sign_update_agg(bytea) IS
'Multi-part message signing aggregate that returns a state which can
then be finalised using crypto_sign_final() or to which other parts
can be added crypto_sign_update() or another message signing aggregate
function.

Note that when signing mutli-part messages using aggregates, the order
in which message parts is processed is critical. You *must* ensure
that the order of messages passed to the aggregate is invariant.';

CREATE OR REPLACE AGGREGATE pgsodium.crypto_sign_update_agg(state bytea, message bytea)
 (
  SFUNC = pgsodium.crypto_sign_update_agg2,
  STYPE = bytea,
  PARALLEL = unsafe);

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


CREATE OR REPLACE VIEW pgsodium.valid_key AS
  SELECT id, name, status, key_type, key_id, key_context, created, expires, associated_data
    FROM pgsodium.key
   WHERE  status IN ('valid', 'default')
     AND CASE WHEN expires IS NULL THEN true ELSE expires > now() END;

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
                coalesce(pgsodium.quote_assoc(m.associated_columns), quote_literal('')),
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

ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_encrypt(bytea, bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_aead_ietf_decrypt(bytea, bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_box_seed_new_keypair(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_open(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_seal(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_box_seal_open(bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_generichash(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_generichash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_generichash(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_shorthash(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_shorthash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_shorthash(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.sodium_bin2base64(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.sodium_base642bin(text) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha512_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256(bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION pgsodium.crypto_auth_hmacsha256_verify(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_kdf_derive_from_key(bigint, bigint, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash_str(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_pwhash_str_verify(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_uniform(integer) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_buf(integer) CALLED ON NULL INPUT;
ALTER FUNCTION randombytes_buf_deterministic(integer, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_secretbox(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_secretbox_open(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox_open(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_secretbox_open(bytea, bytea, uuid) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_hash_sha256(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_hash_sha512(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_seed_new_keypair(bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_sign(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_detached(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_final_create(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_final_verify(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_open(bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_seed_new_keypair(bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_sign_verify_detached(bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_signcrypt_sign_after(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_sign_before(bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_after(bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_before(bytea, bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_signcrypt_verify_public(bytea, bytea, bytea, bytea, bytea, bytea) CALLED ON NULL INPUT;

ALTER FUNCTION crypto_stream_xchacha20(bigint, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20(bigint, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bytea) CALLED ON NULL INPUT;
ALTER FUNCTION crypto_stream_xchacha20_xor_ic(bytea, bytea, bigint, bigint, bytea) CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false)
    RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  view_owner regrole = session_user;
  rule pgsodium.masking_rule;
BEGIN
  SELECT * INTO STRICT rule FROM pgsodium.masking_rule WHERE attrelid = relid and attnum = subid ;

  source_name := relid::regclass;

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

  body = format(
    $c$
    DROP FUNCTION IF EXISTS %s."%s_encrypt_secret"() CASCADE;

    CREATE OR REPLACE FUNCTION %s."%s_encrypt_secret"()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      AS $t$
    BEGIN
    %s;
    RETURN new;
    END;
    $t$;

    ALTER FUNCTION  %s."%s_encrypt_secret"() OWNER TO %s;

    DROP TRIGGER IF EXISTS "%s_encrypt_secret_trigger" ON %s;

    CREATE TRIGGER "%s_encrypt_secret_trigger"
      BEFORE INSERT OR UPDATE ON %s
      FOR EACH ROW
      EXECUTE FUNCTION %s."%s_encrypt_secret" ();
      $c$,
    rule.relnamespace,
    rule.relname,
    rule.relnamespace,
    rule.relname,
    pgsodium.encrypted_columns(relid),
    rule.relnamespace,
    rule.relname,
    view_owner,
    rule.relname,
    source_name,
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
