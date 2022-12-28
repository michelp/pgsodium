
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
        encode(sender, 'base64'),
        encode(recipient, 'base64'), 
        encode(c.ciphertext, 'base64'),
        encode(additional, 'base64'),
        encode(s.signature, 'base64')
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
	receiver OUT bytea,
    message OUT bytea,
    additional OUT bytea)
AS $$
    WITH parts as (
        SELECT decode(parts[1], 'hex') AS version,
               decode(parts[2], 'base64') AS sender,
               decode(parts[3], 'base64') AS receiver,
               decode(parts[4], 'base64') AS ciphertext,
               decode(parts[5], 'base64') AS additional,
               decode(parts[6], 'base64') AS signature
        FROM (SELECT
              regexp_split_to_array(token, '\.') AS parts) I where parts[1] = '0000'),
	
    verify_before AS (
        SELECT state, shared_key
        FROM parts p, pgsodium.crypto_signcrypt_verify_before(
            p.signature,
            p.sender,
            p.receiver,
            p.additional,
            sender_pk,
		    recipient_sk) AS verify_before
    ),
    plaintext AS (
        SELECT pgsodium.crypto_aead_det_decrypt(
            p.ciphertext,
            additional,
            b.shared_key
        ) AS plaintext
        FROM verify_before b, parts p
    ),
	verify_after AS (
		SELECT pgsodium.crypto_signcrypt_verify_after(
		    b.state,
			p.signature,
			sender_pk,
			p.ciphertext
	    ) AS verify_after
	    FROM verify_before b, parts p
	)
    SELECT p.sender, p.receiver, t.plaintext, p.additional from plaintext t, parts p;
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION crypto_signcrypt_token_verify(
    token text, sender_pk bytea) RETURNS bool
AS $$
    WITH parts as (
        SELECT decode(parts[1], 'hex') AS version,
               decode(parts[2], 'base64') AS sender,
               decode(parts[3], 'base64') AS receiver,
               decode(parts[4], 'base64') AS ciphertext,
               decode(parts[5], 'base64') AS additional,
               decode(parts[6], 'base64') AS signature
        FROM (SELECT
              regexp_split_to_array(token, '\.') AS parts) I where parts[1] = '0000')
    SELECT pgsodium.crypto_signcrypt_verify_public(
		p.signature,
		p.sender,
		p.receiver,
		p.additional,
		sender_pk,
		p.ciphertext
	) FROM parts p;
$$ LANGUAGE SQL;
