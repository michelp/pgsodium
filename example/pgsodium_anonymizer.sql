DROP SCHEMA IF EXISTS pgsodium CASCADE;
DROP SCHEMA IF EXISTS anon CASCADE;
DROP EXTENSION IF EXISTS pgsodium CASCADE;
DROP EXTENSION IF EXISTS anon CASCADE;
	
CREATE SCHEMA pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;
CREATE EXTENSION anon CASCADE;
SELECT anon.load();

DROP TABLE IF EXISTS encrypted_record CASCADE;
DROP OWNED BY staff CASCADE;
DROP OWNED BY crypter CASCADE;
DROP ROLE IF EXISTS staff;
DROP ROLE IF EXISTS crypter;
CREATE ROLE staff;
CREATE ROLE crypter;

GRANT pgsodium_keyiduser TO crypter;		
GRANT USAGE ON SCHEMA pgsodium to crypter;

GRANT USAGE ON SCHEMA anon TO crypter;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA anon TO crypter, staff;
GRANT SELECT ON ALL TABLES IN SCHEMA anon TO crypter, staff;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA anon TO crypter, staff;

CREATE TABLE encrypted_record (
    id bigserial primary key,
    key_id bigint not null default 1,
	nonce bytea,
	encrypted_json bytea
    );

CREATE OR REPLACE FUNCTION encrypted_record_check() RETURNS trigger
	SECURITY DEFINER
    LANGUAGE plpgsql AS
$$
BEGIN
	PERFORM pgsodium.crypto_secretbox_open(
            	new.encrypted_json,
             	new.nonce,
             	new.key_id);
	RETURN new;
END;
$$;

ALTER FUNCTION encrypted_record_check OWNER TO crypter;

CREATE TRIGGER encrypted_record_check_trigger
    BEFORE INSERT ON encrypted_record
    FOR EACH ROW
    EXECUTE FUNCTION encrypted_record_check();

REVOKE ALL ON TABLE encrypted_record FROM PUBLIC;
GRANT SELECT (id) ON TABLE encrypted_record TO staff;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE encrypted_record TO crypter;
GRANT USAGE ON SEQUENCE encrypted_record_id_seq TO crypter;

CREATE OR REPLACE FUNCTION decrypt_record(bigint)
	RETURNS TABLE (
	    id bigint,
		first_name text,
		last_name text,
	    age integer,
	    secret text,
	    signup_date timestamptz)
    LANGUAGE sql
    SECURITY DEFINER
	AS $$
    SELECT e.id, rec.*
	 FROM (SELECT * FROM encrypted_record WHERE id = $1) e
	LEFT JOIN LATERAL (
		SELECT x.* FROM json_to_record(
			convert_from(
			pgsodium.crypto_secretbox_open(
            	e.encrypted_json,
             	e.nonce,
             	e.key_id), 'utf8')::json)
	AS
	x(first_name text,
	  last_name text,
	  age int,
	  secret text,
	  signup_date timestamptz)) rec on true;
	$$;

REVOKE ALL ON FUNCTION decrypt_record FROM PUBLIC;
ALTER FUNCTION decrypt_record OWNER TO crypter;
GRANT EXECUTE ON FUNCTION decrypt_record TO crypter;

CREATE OR REPLACE FUNCTION pseudo_record(bigint)
	RETURNS TABLE (
	    id bigint,
		first_name text,
		last_name text,
	    age_range int4range,
	    secret text,
	    signup_month timestamptz)
    LANGUAGE sql
    SECURITY DEFINER
	AS $$
    SELECT e.id,
		anon.pseudo_first_name(rec.first_name) AS first_name,
		anon.pseudo_last_name(rec.last_name) AS last_name,
		anon.generalize_int4range(rec.age, 5) AS age,
		anon.partial(rec.secret, 2, 'xxxxxxxxx', 2) as hidden_secret,
	    lower(anon.generalize_tstzrange(rec.signup_date, 'month')) AS secret_month
	 FROM (SELECT * FROM encrypted_record WHERE id = $1) e
	LEFT JOIN LATERAL decrypt_record(e.id) rec on true;
	$$;

ALTER FUNCTION pseudo_record OWNER TO crypter;
	
CREATE OR REPLACE FUNCTION encrypt_record(
		first_name text,
		last_name text,
		age int,
		secret text,
		signup_date timestamptz) RETURNS bigint
    LANGUAGE plpgsql
	SECURITY DEFINER
AS
$$
DECLARE
    new_nonce bytea;
    encrypted_record_id bigint;
	payload jsonb;
BEGIN
	new_nonce = pgsodium.crypto_secretbox_noncegen();
	payload = json_build_object(
		'first_name', first_name,
		'last_name', last_name,
		'age', age,
		'secret', secret,
		'signup_date', signup_date);
	
    INSERT INTO encrypted_record (nonce) VALUES (new_nonce)
	    RETURNING id INTO encrypted_record_id;
	
    UPDATE encrypted_record SET
	    encrypted_json = pgsodium.crypto_secretbox(
            convert_to(payload::text, 'utf8'),
            new_nonce,
            key_id)
    WHERE id = encrypted_record_id;
    RETURN encrypted_record_id;
END;
$$;

ALTER FUNCTION encrypt_record OWNER TO crypter;


CREATE OR REPLACE FUNCTION rotate_key(encrypted_record_id bigint, new_key bigint)
    RETURNS void
	SECURITY DEFINER
	LANGUAGE plpgsql AS $$
DECLARE
    new_nonce bytea;
BEGIN
    new_nonce = pgsodium.crypto_secretbox_noncegen();
    UPDATE encrypted_record SET
    nonce = new_nonce,
    key_id = new_key,
    encrypted_json = pgsodium.crypto_secretbox(
        pgsodium.crypto_secretbox_open(
             encrypted_record.encrypted_json,
             encrypted_record.nonce,
             encrypted_record.key_id),
        new_nonce,
        new_key)
    WHERE encrypted_record.id = encrypted_record_id;
    RETURN;
END;
$$;

ALTER FUNCTION rotate_key OWNER TO crypter;

CREATE OR REPLACE FUNCTION demo_data(
	num_records bigint,
	start_date timestamptz = '2010-01-01',
	end_date timestamptz = '2020-01-01')
    RETURNS void
	LANGUAGE sql
	SECURITY DEFINER
AS $$
	SELECT encrypt_record(anon.fake_first_name(),
     anon.fake_last_name(),
	 anon.random_int_between(0, 110),
	 anon.random_city(),
	 anon.random_date_between(start_date, end_date))
	FROM generate_series(1, num_records);
$$;

ALTER FUNCTION demo_data OWNER TO crypter;
