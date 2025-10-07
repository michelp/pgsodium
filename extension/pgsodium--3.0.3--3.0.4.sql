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
  FOR m IN SELECT * FROM pgsodium.mask_columns(relid) LOOP
    IF m.key_id IS NULL AND m.key_id_column is NULL THEN
      CONTINUE;
    ELSE
      expression := expression || comma;
      expression := expression || format(
        $f$%s = pg_catalog.encode(
          pgsodium.crypto_aead_det_encrypt(
            pg_catalog.convert_to(%s, 'utf8'),
            pg_catalog.convert_to(%s::text, 'utf8'),
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
            pg_catalog.convert_to(%s::text, 'utf8'),
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
