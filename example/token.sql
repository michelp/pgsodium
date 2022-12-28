-- experimental signcrypt token

CREATE OR REPLACE FUNCTION crypto_signcrypt_token_encrypt(
    sender bytea,
    recipient bytea,
    sender_sk bytea,
    recipient_pk bytea,
    message bytea,
    additional bytea)
RETURNS text AS $$
WITH
    sign_before AS (
        SELECT state, shared_key
        FROM pgsodium.crypto_signcrypt_sign_before(
            sender,
            recipient,
            sender_sk,
            recipient_pk,
            additional)
    ),
    ciphertext AS (
        SELECT pgsodium.crypto_aead_det_encrypt(
            message,
            additional,
            b.shared_key
        ) AS ciphertext
        FROM sign_before b
    ),
    signature AS (
        SELECT pgsodium.crypto_signcrypt_sign_after(
            b.state,
            sender_sk,
            c.ciphertext
        ) AS signature
        FROM
            sign_before b,
            ciphertext c
    )
    SELECT format(
        '0000.%s.%s.%s.%s.%s',
        pgsodium.sodium_bin2base64(sender),
        pgsodium.sodium_bin2base64(recipient),
        pgsodium.sodium_bin2base64(c.ciphertext),
        pgsodium.sodium_bin2base64(additional),
        pgsodium.sodium_bin2base64(s.signature)
    )
    FROM
        ciphertext c,
        signature s;
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION crypto_signcrypt_token_decrypt(
    token text,
    sender_pk bytea,
    recipient_sk bytea,
    sender OUT bytea,
    message OUT bytea,
    additional OUT bytea)
AS $$
    WITH parts as (
        SELECT decode(parts[1], 'hex') AS version,
               pgsodium.sodium_base642bin(parts[2]) AS sender,
               pgsodium.sodium_base642bin(parts[3]) AS receiver,
               pgsodium.sodium_base642bin(parts[4]) AS ciphertext,
               pgsodium.sodium_base642bin(parts[5]) AS additional,
               pgsodium.sodium_base642bin(parts[6]) AS signature
        FROM (SELECT
              regexp_split_to_array(token, '\.') AS parts) I where parts[1] = '0000')
    SELECT sender, ciphertext, additional from parts;
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION crypto_signcrypt_token_verify(
    token text,
    sender_pk bytea,
    sender OUT bytea,
    message OUT bytea,
    additional OUT bytea)
AS $$
    SELECT NULL::bytea, NULL::bytea, NULL::bytea;
$$ LANGUAGE SQL;
