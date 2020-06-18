BEGIN;
CREATE SCHEMA pgsodium;
DROP EXTENSION IF EXISTS pgsodium;
CREATE EXTENSION pgsodium WITH SCHEMA pgsodium;

-- create two roles to test with

CREATE ROLE auser;
CREATE ROLE buser;

-- encrypted user data, RLS policy for extra goodness
CREATE TABLE encrypted_user_data (
    id bigserial primary key,
    user_name text,
    user_data bytea
    );

ALTER TABLE encrypted_user_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY encrypted_user_data_policy ON encrypted_user_data
    USING (user_name = current_user);

-- mapping of role to derivation key, users can only see their own key
CREATE TABLE encryption_role_key (
    user_name text PRIMARY KEY,
    key_id bigint NOT null DEFAULT 1,
    nonce bytea NOT null
    );

ALTER TABLE encryption_role_key ENABLE ROW LEVEL SECURITY;

CREATE POLICY encryption_role_key_policy ON encrypted_user_data
    USING (user_name = current_user);

-- regular users cannot call pgsodium API

REVOKE ALL ON schema pgsodium FROM auser, buser;

-- decrypt function does the decyption work, cannot reveal key

CREATE OR REPLACE FUNCTION user_decrypt_text(bytea, bytea, bigint)
    RETURNS text SECURITY DEFINER LANGUAGE sql AS $$
SELECT convert_from(pgsodium.crypto_secretbox_open(
         $1,
         $2,
         pgsodium.pgsodium_derive($3)), 'utf8')
$$;

-- this is the view users can use that wraps the encrypted_user_data
-- table and shows only decrypted content for the set user

CREATE OR REPLACE VIEW user_view AS
    SELECT id, user_name,
    user_decrypt_text(d.user_data, e.nonce, e.key_id)
    AS user_data FROM encrypted_user_data d JOIN encryption_role_key e
    USING (user_name);

-- trigger to encrypt data INSTEAD OF insert into the test_view
CREATE OR REPLACE FUNCTION user_encrypt() RETURNS trigger
    SECURITY DEFINER LANGUAGE plpgsql AS $$
DECLARE
    user_id bigint;
    role_key encryption_role_key;
BEGIN
    INSERT INTO encryption_role_key (user_name,

    UPDATE encrypted_user_data
    SET user_data = pgsodium.crypto_secretbox(
        convert_to(new.user_data, 'utf8'),
        new_nonce,
        pgsodium.pgsodium_derive(key_id))
    where id = user_id;
    RETURN new;
END;
$$;

CREATE TRIGGER user_encrypt_trigger
    INSTEAD OF INSERT ON user_view
    FOR EACH ROW
    EXECUTE FUNCTION user_encrypt();

-- key rotation function, auser and buser can't call this

CREATE OR REPLACE FUNCTION rotate_key(user_role text, new_key bigint)
    RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    new_nonce bytea;
    old_role_key encryption_role_key;
BEGIN
    SELECT * INTO old_role_key
    FROM encryption_role_key
    WHERE user_name = user_role;

    new_nonce = pgsodium.crypto_secretbox_noncegen();

    UPDATE encrypted_user_data SET
        nonce = new_nonce,
        key_id = new_key,
        user_data = pgsodium.crypto_secretbox(
            pgsodium.crypto_secretbox_open(
                 encrypted_user_data.user_data,
                 old_role_key.nonce,
                 pgsodium.pgsodium_derive(old_role_key.key_id)),
            new_nonce,
            pgsodium.pgsodium_derive(new_key))
    WHERE user_name = user_role;
    RETURN;
END;
$$;

COMMIT;
