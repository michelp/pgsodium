BEGIN;    
CREATE SCHEMA pgsodium;
DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

DROP TABLE IF EXISTS test CASCADE;

CREATE TABLE test (
    id bigserial primary key,
    key_id bigint not null default 1,
    nonce bytea not null,
    data bytea
    );

create or replace view test_view as
    select id,
    convert_from(pgsodium.crypto_secretbox_open(
             data,
             nonce,
             pgsodium.pgsodium_derive(key_id)),
    'utf8') as data from test;

CREATE OR REPLACE FUNCTION test_encrypt() RETURNS trigger
    language plpgsql AS
$$
DECLARE
    new_nonce bytea = pgsodium.crypto_secretbox_noncegen();
    test_id bigint;
BEGIN
    
    insert into test (nonce) values (new_nonce) returning id into test_id;
    update test set data = pgsodium.crypto_secretbox(
        convert_to(new.data, 'utf8'),
        new_nonce,
        pgsodium.pgsodium_derive(key_id))
    where id = test_id;
    RETURN new;
END;
$$;

CREATE TRIGGER test_encrypt_trigger
    INSTEAD OF INSERT ON test_view
    FOR EACH ROW
    EXECUTE FUNCTION test_encrypt();

CREATE OR REPLACE FUNCTION rotate_key(test_id bigint, new_key bigint) RETURNS void LANGUAGE plpgsql AS $$
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
             pgsodium.pgsodium_derive(test.key_id)),
        new_nonce,
        pgsodium.pgsodium_derive(new_key))
    WHERE test.id = test_id;
    RETURN;
END;
$$;

COMMIT;
