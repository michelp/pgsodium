CREATE SCHEMA IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;

-- This is a demonstration user to show that the pgsodium_keyiduser
-- role can be used to access only encryption functions by key_id,
-- this role can never access raw encryption keys.
	
CREATE ROLE auser;
GRANT pgsodium_keyiduser TO auser;
GRANT USAGE ON SCHEMA pgsodium TO auser;

SET ROLE auser;

CREATE TABLE IF NOT EXISTS  test (
    id bigserial primary key,
    key_id bigint not null default 1,
    nonce bytea not null,
    data bytea
    );

CREATE OR REPLACE VIEW test_view AS
    SELECT id,
    convert_from(
		pgsodium.crypto_secretbox_open(
             data,
             nonce,
             key_id),
    'utf8') AS data FROM test;

CREATE OR REPLACE FUNCTION test_encrypt() RETURNS trigger
    language plpgsql AS
$$
DECLARE
    new_nonce bytea = pgsodium.crypto_secretbox_noncegen();
    test_id bigint;
BEGIN

    INSERT INTO test (nonce) VALUES (new_nonce) RETURNING ID INTO test_id;
    UPDATE test SET
	    data = pgsodium.crypto_secretbox(
            convert_to(new.data, 'utf8'),
            new_nonce,
            key_id)
    WHERE id = test_id;
    RETURN new;
END;
$$;

CREATE TRIGGER test_encrypt_trigger
    INSTEAD OF INSERT ON test_view
    FOR EACH ROW
    EXECUTE FUNCTION test_encrypt();

CREATE OR REPLACE FUNCTION rotate_key(test_id bigint, new_key bigint)
    RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    new_nonce bytea;
BEGIN
    new_nonce = pgsodium.crypto_secretbox_noncegen();
    UPDATE test SET
    nonce = new_nonce,
    key_id = new_key,
    data = pgsodium.crypto_secretbox(
        pgsodium.crypto_secretbox_open(
             test.data,
             test.nonce,
             test.key_id),
        new_nonce,
        new_key)
    WHERE test.id = test_id;
    RETURN;
END;
$$;
\echo
\echo Try inserting some data in test_view like:
\echo "    postgres=> insert into test_view (data) values ('this is one'), ('this is two');"
\echo Type RESET ROLE; to get back to previous user

insert into test_view (data) values ('this is one'), ('this is two');    
