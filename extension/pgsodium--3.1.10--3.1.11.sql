-- pgsodium 3.1.11: IP address encryption (libsodium crypto_ipcrypt_*)
--
-- Implements the ipcrypt-std family (https://ipcrypt-std.github.io):
--   * deterministic  (AES-128, format-preserving)
--   * pfx            (prefix-preserving)
--   * nd             (KIASU-BC, non-deterministic, 8 byte tweak)
--   * ndx            (AES-XTS, non-deterministic, 16 byte tweak)
--
-- IP addresses are handled as the 16 byte binary form; the ip2bin/bin2ip
-- helpers convert to/from text, and inet overloads are provided for the two
-- format-preserving variants.

-- New key types for the managed key infrastructure (one per variant).
ALTER TYPE pgsodium.key_type ADD VALUE 'ipcrypt-det';
ALTER TYPE pgsodium.key_type ADD VALUE 'ipcrypt-pfx';
ALTER TYPE pgsodium.key_type ADD VALUE 'ipcrypt-nd';
ALTER TYPE pgsodium.key_type ADD VALUE 'ipcrypt-ndx';

-- Conversion helpers between text IP addresses and the 16 byte binary form.

CREATE FUNCTION pgsodium.crypto_ipcrypt_ip2bin(ip text)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ip2bin'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_bin2ip(bin bytea)
  RETURNS text
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_bin2ip'
  LANGUAGE C IMMUTABLE STRICT;

-- ===========================================================================
-- Deterministic variant (key 16, input/output 16, format-preserving)
-- ===========================================================================

CREATE FUNCTION pgsodium.crypto_ipcrypt_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_keygen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_encrypt(ip bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_encrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_decrypt(ip bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_decrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_encrypt(ip bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_encrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_decrypt(ip bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_decrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_encrypt(ip bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-det';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_encrypt(ip, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_encrypt(ip, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

CREATE FUNCTION pgsodium.crypto_ipcrypt_decrypt(ip bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-det';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_decrypt(ip, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_decrypt(ip, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

-- inet overloads (format-preserving): encrypt/decrypt inet -> inet
CREATE FUNCTION pgsodium.crypto_ipcrypt_encrypt(ip inet, key bytea)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_encrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key))::inet;
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_decrypt(ip inet, key bytea)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_decrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key))::inet;
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_encrypt(ip inet, key_uuid uuid)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_encrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key_uuid))::inet;
$$ LANGUAGE sql STABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_decrypt(ip inet, key_uuid uuid)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_decrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key_uuid))::inet;
$$ LANGUAGE sql STABLE STRICT;

-- ===========================================================================
-- Prefix-preserving variant (key 32, input/output 16, prefix-preserving)
-- ===========================================================================

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_pfx_keygen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_encrypt(ip bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_pfx_encrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_decrypt(ip bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_pfx_decrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_encrypt(ip bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_pfx_encrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_decrypt(ip bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_pfx_decrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_encrypt(ip bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-pfx';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_pfx_encrypt(ip, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_pfx_encrypt(ip, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_decrypt(ip bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-pfx';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_pfx_decrypt(ip, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_pfx_decrypt(ip, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_encrypt(ip inet, key bytea)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_pfx_encrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key))::inet;
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_decrypt(ip inet, key bytea)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_pfx_decrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key))::inet;
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_encrypt(ip inet, key_uuid uuid)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_pfx_encrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key_uuid))::inet;
$$ LANGUAGE sql STABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_pfx_decrypt(ip inet, key_uuid uuid)
  RETURNS inet AS $$
  SELECT pgsodium.crypto_ipcrypt_bin2ip(
           pgsodium.crypto_ipcrypt_pfx_decrypt(
             pgsodium.crypto_ipcrypt_ip2bin(host(ip)), key_uuid))::inet;
$$ LANGUAGE sql STABLE STRICT;

-- ===========================================================================
-- Non-deterministic variant ND (key 16, tweak 8, input 16, output 24)
-- ===========================================================================

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_keygen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_tweakgen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_tweakgen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_encrypt(ip bytea, tweak bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_encrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_decrypt(ciphertext bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_decrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_encrypt(ip bytea, tweak bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_encrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_decrypt(ciphertext bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_nd_decrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_encrypt(ip bytea, tweak bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-nd';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_nd_encrypt(ip, tweak, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_nd_encrypt(ip, tweak, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

CREATE FUNCTION pgsodium.crypto_ipcrypt_nd_decrypt(ciphertext bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-nd';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_nd_decrypt(ciphertext, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_nd_decrypt(ciphertext, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

-- ===========================================================================
-- Extended non-deterministic variant NDX (key 32, tweak 16, input 16, output 32)
-- ===========================================================================

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_keygen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_keygen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_tweakgen()
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_tweakgen'
  LANGUAGE C VOLATILE;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_encrypt(ip bytea, tweak bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_encrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_decrypt(ciphertext bytea, key bytea)
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_decrypt'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_encrypt(ip bytea, tweak bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_encrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_decrypt(ciphertext bytea, key_id bigint, context bytea = 'pgsodium')
  RETURNS bytea
  AS '$libdir/pgsodium', 'pgsodium_crypto_ipcrypt_ndx_decrypt_by_id'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_encrypt(ip bytea, tweak bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-ndx';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_ndx_encrypt(ip, tweak, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_ndx_encrypt(ip, tweak, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

CREATE FUNCTION pgsodium.crypto_ipcrypt_ndx_decrypt(ciphertext bytea, key_uuid uuid)
  RETURNS bytea AS $$
DECLARE
  key pgsodium.decrypted_key;
BEGIN
  SELECT * INTO STRICT key FROM pgsodium.decrypted_key v
    WHERE id = key_uuid AND key_type = 'ipcrypt-ndx';
  IF key.decrypted_raw_key IS NOT NULL THEN
    RETURN pgsodium.crypto_ipcrypt_ndx_decrypt(ciphertext, key.decrypted_raw_key);
  END IF;
  RETURN pgsodium.crypto_ipcrypt_ndx_decrypt(ciphertext, key.key_id, key.key_context);
END;
$$ LANGUAGE plpgsql STRICT STABLE SECURITY DEFINER SET search_path = '';

-- ===========================================================================
-- Permissions
-- ===========================================================================

-- by_id (bigint), uuid and inet/uuid overloads are restricted to
-- pgsodium_keyiduser, matching the convention for managed-key functions.
DO $$
DECLARE
  func text;
BEGIN
  FOREACH func IN ARRAY ARRAY[
    'pgsodium.crypto_ipcrypt_encrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_decrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_encrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_encrypt(inet, uuid)',
    'pgsodium.crypto_ipcrypt_decrypt(inet, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_encrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_pfx_decrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_pfx_encrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_encrypt(inet, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_decrypt(inet, uuid)',
    'pgsodium.crypto_ipcrypt_nd_encrypt(bytea, bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_nd_decrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_nd_encrypt(bytea, bytea, uuid)',
    'pgsodium.crypto_ipcrypt_nd_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_ndx_encrypt(bytea, bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_ndx_decrypt(bytea, bigint, bytea)',
    'pgsodium.crypto_ipcrypt_ndx_encrypt(bytea, bytea, uuid)',
    'pgsodium.crypto_ipcrypt_ndx_decrypt(bytea, uuid)'
  ]
  LOOP
    EXECUTE pg_catalog.format($i$
      REVOKE ALL ON FUNCTION %s FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION %s TO pgsodium_keyiduser;
    $i$, func, func);
  END LOOP;

  -- The uuid overloads are SECURITY DEFINER and must be owned by a role that
  -- can read pgsodium.key (pgsodium_keymaker).
  FOREACH func IN ARRAY ARRAY[
    'pgsodium.crypto_ipcrypt_encrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_encrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_pfx_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_nd_encrypt(bytea, bytea, uuid)',
    'pgsodium.crypto_ipcrypt_nd_decrypt(bytea, uuid)',
    'pgsodium.crypto_ipcrypt_ndx_encrypt(bytea, bytea, uuid)',
    'pgsodium.crypto_ipcrypt_ndx_decrypt(bytea, uuid)'
  ]
  LOOP
    EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO pgsodium_keymaker;', func);
  END LOOP;
END
$$;
