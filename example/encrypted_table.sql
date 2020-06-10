BEGIN;    
CREATE SCHEMA pgsodium;
DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

DROP TABLE IF EXISTS test CASCADE;

CREATE TABLE test (
    id bigserial primary key,
    nonce bytea,
    data bytea
    );

create or replace view test_view as
    select id,
    convert_from(pgsodium.crypto_secretbox_open(
             data,
             nonce,
             pgsodium.pgsodium_derive(id)),
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
        pgsodium.pgsodium_derive(test_id))
    where id = test_id;
    RETURN new;
END;
$$;

CREATE TRIGGER test_encrypt_trigger
    INSTEAD OF INSERT ON test_view
    FOR EACH ROW
    EXECUTE FUNCTION test_encrypt();

COMMIT;
