
ALTER FUNCTION @extschema@.crypto_aead_det_encrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea) CALLED ON NULL INPUT;
ALTER FUNCTION @extschema@.crypto_aead_det_decrypt(message bytea, additional bytea, key_uuid uuid, nonce bytea) CALLED ON NULL INPUT;  
