-- crypto_ipcrypt_* tests
--
-- Known-answer test vectors are taken from the ipcrypt-std reference
-- implementation (jedisct1/draft-denis-ipcrypt, implementations/python/test_vectors.json).

-- ===========================================================================
-- Conversion helpers
-- ===========================================================================

SELECT is(crypto_ipcrypt_bin2ip(crypto_ipcrypt_ip2bin('192.0.2.1')), '192.0.2.1',
          'ip2bin/bin2ip IPv4 round-trip');
SELECT is(crypto_ipcrypt_bin2ip(crypto_ipcrypt_ip2bin('2001:db8::1')), '2001:db8::1',
          'ip2bin/bin2ip IPv6 round-trip');
SELECT is(octet_length(crypto_ipcrypt_ip2bin('192.0.2.1')), 16, 'ip2bin is 16 bytes');
SELECT throws_ok($$select crypto_ipcrypt_ip2bin('not-an-ip')$$,
          '22000', 'pgsodium_crypto_ipcrypt_ip2bin: invalid IP address',
          'ip2bin rejects garbage');
SELECT throws_ok($$select crypto_ipcrypt_bin2ip('short'::bytea)$$,
          '22000', 'pgsodium_crypto_ipcrypt_bin2ip: input must be 16 bytes',
          'bin2ip rejects wrong size');

-- ===========================================================================
-- Deterministic variant
-- ===========================================================================

SELECT crypto_ipcrypt_keygen() detkey \gset
SELECT is(octet_length(:'detkey'::bytea), 16, 'ipcrypt det keygen is 16 bytes');

-- ipcrypt-std known-answer test (the correctness gate)
SELECT is(crypto_ipcrypt_encrypt('192.0.2.1'::inet,
            '\x2b7e151628aed2a6abf7158809cf4f3c'::bytea),
          '1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777'::inet,
          'ipcrypt det matches ipcrypt-std KAT (192.0.2.1)');
SELECT is(crypto_ipcrypt_encrypt('0.0.0.0'::inet,
            '\x0123456789abcdeffedcba9876543210'::bytea),
          'bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb'::inet,
          'ipcrypt det matches ipcrypt-std KAT (0.0.0.0)');

-- determinism + round-trip + format preservation (output is 16 bytes)
SELECT crypto_ipcrypt_ip2bin('203.0.113.5') detip \gset
SELECT crypto_ipcrypt_encrypt(:'detip'::bytea, :'detkey'::bytea) detct \gset
SELECT is(crypto_ipcrypt_encrypt(:'detip'::bytea, :'detkey'::bytea), :'detct'::bytea,
          'ipcrypt det is deterministic');
SELECT is(crypto_ipcrypt_decrypt(:'detct'::bytea, :'detkey'::bytea), :'detip'::bytea,
          'ipcrypt det decrypt round-trip');
SELECT is(octet_length(:'detct'::bytea), 16, 'ipcrypt det output is 16 bytes');
SELECT is(crypto_ipcrypt_decrypt(crypto_ipcrypt_encrypt('203.0.113.5'::inet, :'detkey'::bytea),
            :'detkey'::bytea),
          '203.0.113.5'::inet, 'ipcrypt det inet round-trip');

SELECT throws_ok($$select crypto_ipcrypt_encrypt('\x00000000000000000000000000000000'::bytea, 'short'::bytea)$$,
          '22000', 'pgsodium_crypto_ipcrypt_encrypt: invalid key',
          'ipcrypt det rejects bad key size');

-- ===========================================================================
-- Prefix-preserving variant (PFX)
-- ===========================================================================

SELECT crypto_ipcrypt_pfx_keygen() pfxkey \gset
SELECT is(octet_length(:'pfxkey'::bytea), 32, 'ipcrypt pfx keygen is 32 bytes');

-- ipcrypt-std KAT: family-preserving (IPv4 -> IPv4)
SELECT is(crypto_ipcrypt_pfx_encrypt('192.0.2.1'::inet,
            '\x0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301'::bytea),
          '100.115.72.131'::inet,
          'ipcrypt pfx matches ipcrypt-std KAT (192.0.2.1)');

-- ipcrypt-std KAT: prefix preservation.  Three addresses in 10.0.0.0/24
-- encrypt to three addresses sharing the prefix 19.214.210.0/24.
SELECT is(crypto_ipcrypt_pfx_encrypt('10.0.0.47'::inet,
            '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea),
          '19.214.210.244'::inet, 'ipcrypt pfx KAT 10.0.0.47');
SELECT is(crypto_ipcrypt_pfx_encrypt('10.0.0.129'::inet,
            '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea),
          '19.214.210.80'::inet, 'ipcrypt pfx KAT 10.0.0.129');
SELECT is(crypto_ipcrypt_pfx_encrypt('10.0.0.234'::inet,
            '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea),
          '19.214.210.30'::inet, 'ipcrypt pfx KAT 10.0.0.234');
-- the shared /24 prefix is preserved across all three ciphertexts
SELECT is(count(DISTINCT network(set_masklen(ct, 24)))::int, 1,
          'ipcrypt pfx preserves the /24 prefix')
  FROM (VALUES
    (crypto_ipcrypt_pfx_encrypt('10.0.0.47'::inet,  '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea)),
    (crypto_ipcrypt_pfx_encrypt('10.0.0.129'::inet, '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea)),
    (crypto_ipcrypt_pfx_encrypt('10.0.0.234'::inet, '\x2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a'::bytea))
  ) AS t(ct);

-- round-trip + bad key
SELECT is(crypto_ipcrypt_pfx_decrypt(crypto_ipcrypt_pfx_encrypt('198.51.100.23'::inet, :'pfxkey'::bytea),
            :'pfxkey'::bytea),
          '198.51.100.23'::inet, 'ipcrypt pfx inet round-trip');
SELECT throws_ok($$select crypto_ipcrypt_pfx_encrypt('\x00000000000000000000000000000000'::bytea, 'short'::bytea)$$,
          '22000', 'pgsodium_crypto_ipcrypt_pfx_encrypt: invalid key',
          'ipcrypt pfx rejects bad key size');

-- ===========================================================================
-- Non-deterministic variant ND
-- ===========================================================================

SELECT crypto_ipcrypt_nd_keygen() ndkey \gset
SELECT is(octet_length(:'ndkey'::bytea), 16, 'ipcrypt nd keygen is 16 bytes');
SELECT is(octet_length(crypto_ipcrypt_nd_tweakgen()), 8, 'ipcrypt nd tweakgen is 8 bytes');

-- ipcrypt-std KAT (fixed tweak)
SELECT is(crypto_ipcrypt_nd_encrypt(crypto_ipcrypt_ip2bin('0.0.0.0'),
            '\x08e0c289bff23b7c'::bytea,
            '\x0123456789abcdeffedcba9876543210'::bytea),
          '\x08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16'::bytea,
          'ipcrypt nd matches ipcrypt-std KAT');

-- two encryptions with fresh tweaks differ but both decrypt back
SELECT crypto_ipcrypt_ip2bin('192.0.2.99') ndip \gset
SELECT crypto_ipcrypt_nd_encrypt(:'ndip'::bytea, crypto_ipcrypt_nd_tweakgen(), :'ndkey'::bytea) ndct1 \gset
SELECT crypto_ipcrypt_nd_encrypt(:'ndip'::bytea, crypto_ipcrypt_nd_tweakgen(), :'ndkey'::bytea) ndct2 \gset
SELECT is(octet_length(:'ndct1'::bytea), 24, 'ipcrypt nd output is 24 bytes');
SELECT isnt(:'ndct1'::bytea, :'ndct2'::bytea, 'ipcrypt nd is non-deterministic across tweaks');
SELECT is(crypto_ipcrypt_nd_decrypt(:'ndct1'::bytea, :'ndkey'::bytea), :'ndip'::bytea, 'ipcrypt nd decrypt ct1');
SELECT is(crypto_ipcrypt_nd_decrypt(:'ndct2'::bytea, :'ndkey'::bytea), :'ndip'::bytea, 'ipcrypt nd decrypt ct2');

SELECT throws_ok(format($$select crypto_ipcrypt_nd_encrypt(%L::bytea, 'bad'::bytea, %L::bytea)$$, :'ndip', :'ndkey'),
          '22000', 'pgsodium_crypto_ipcrypt_nd_encrypt: invalid tweak',
          'ipcrypt nd rejects bad tweak size');

-- ===========================================================================
-- Extended non-deterministic variant NDX
-- ===========================================================================

SELECT crypto_ipcrypt_ndx_keygen() ndxkey \gset
SELECT is(octet_length(:'ndxkey'::bytea), 32, 'ipcrypt ndx keygen is 32 bytes');
SELECT is(octet_length(crypto_ipcrypt_ndx_tweakgen()), 16, 'ipcrypt ndx tweakgen is 16 bytes');

-- ipcrypt-std KAT (fixed tweak)
SELECT is(crypto_ipcrypt_ndx_encrypt(crypto_ipcrypt_ip2bin('0.0.0.0'),
            '\x21bd1834bc088cd2b4ecbe30b70898d7'::bytea,
            '\x0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301'::bytea),
          '\x21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5'::bytea,
          'ipcrypt ndx matches ipcrypt-std KAT');

SELECT crypto_ipcrypt_ip2bin('198.51.100.7') ndxip \gset
SELECT crypto_ipcrypt_ndx_encrypt(:'ndxip'::bytea, crypto_ipcrypt_ndx_tweakgen(), :'ndxkey'::bytea) ndxct1 \gset
SELECT crypto_ipcrypt_ndx_encrypt(:'ndxip'::bytea, crypto_ipcrypt_ndx_tweakgen(), :'ndxkey'::bytea) ndxct2 \gset
SELECT is(octet_length(:'ndxct1'::bytea), 32, 'ipcrypt ndx output is 32 bytes');
SELECT isnt(:'ndxct1'::bytea, :'ndxct2'::bytea, 'ipcrypt ndx is non-deterministic across tweaks');
SELECT is(crypto_ipcrypt_ndx_decrypt(:'ndxct1'::bytea, :'ndxkey'::bytea), :'ndxip'::bytea, 'ipcrypt ndx decrypt ct1');
SELECT is(crypto_ipcrypt_ndx_decrypt(:'ndxct2'::bytea, :'ndxkey'::bytea), :'ndxip'::bytea, 'ipcrypt ndx decrypt ct2');

-- ===========================================================================
-- Server-managed keys (by_id and uuid) -- only when server keys are available
-- ===========================================================================

\if :serverkeys
  SET ROLE pgsodium_keyiduser;

  -- deterministic by_id (bigint)
  SELECT is(crypto_ipcrypt_decrypt(crypto_ipcrypt_encrypt(:'detip'::bytea, 1::bigint), 1::bigint),
            :'detip'::bytea, 'ipcrypt det by_id round-trip');
  -- pfx by_id
  SELECT is(crypto_ipcrypt_pfx_decrypt(crypto_ipcrypt_pfx_encrypt(:'detip'::bytea, 2::bigint), 2::bigint),
            :'detip'::bytea, 'ipcrypt pfx by_id round-trip');
  -- nd by_id (tweak supplied)
  SELECT is(crypto_ipcrypt_nd_decrypt(
              crypto_ipcrypt_nd_encrypt(:'ndip'::bytea, crypto_ipcrypt_nd_tweakgen(), 3::bigint), 3::bigint),
            :'ndip'::bytea, 'ipcrypt nd by_id round-trip');
  -- ndx by_id
  SELECT is(crypto_ipcrypt_ndx_decrypt(
              crypto_ipcrypt_ndx_encrypt(:'ndxip'::bytea, crypto_ipcrypt_ndx_tweakgen(), 4::bigint), 4::bigint),
            :'ndxip'::bytea, 'ipcrypt ndx by_id round-trip');

  RESET ROLE;

  -- uuid-managed keys
  SELECT id AS det_kid  FROM create_key('ipcrypt-det') \gset
  SELECT id AS pfx_kid  FROM create_key('ipcrypt-pfx') \gset
  SELECT id AS nd_kid   FROM create_key('ipcrypt-nd')  \gset
  SELECT id AS ndx_kid  FROM create_key('ipcrypt-ndx') \gset

  SET ROLE pgsodium_keyiduser;

  SELECT is(crypto_ipcrypt_decrypt(crypto_ipcrypt_encrypt(:'detip'::bytea, :'det_kid'::uuid), :'det_kid'::uuid),
            :'detip'::bytea, 'ipcrypt det by uuid round-trip');
  -- deterministic: same input + same key uuid -> same output
  SELECT is(crypto_ipcrypt_encrypt(:'detip'::bytea, :'det_kid'::uuid),
            crypto_ipcrypt_encrypt(:'detip'::bytea, :'det_kid'::uuid),
            'ipcrypt det by uuid is deterministic');
  SELECT is(crypto_ipcrypt_pfx_decrypt(crypto_ipcrypt_pfx_encrypt(:'detip'::bytea, :'pfx_kid'::uuid), :'pfx_kid'::uuid),
            :'detip'::bytea, 'ipcrypt pfx by uuid round-trip');
  SELECT is(crypto_ipcrypt_nd_decrypt(
              crypto_ipcrypt_nd_encrypt(:'ndip'::bytea, crypto_ipcrypt_nd_tweakgen(), :'nd_kid'::uuid), :'nd_kid'::uuid),
            :'ndip'::bytea, 'ipcrypt nd by uuid round-trip');
  SELECT is(crypto_ipcrypt_ndx_decrypt(
              crypto_ipcrypt_ndx_encrypt(:'ndxip'::bytea, crypto_ipcrypt_ndx_tweakgen(), :'ndx_kid'::uuid), :'ndx_kid'::uuid),
            :'ndxip'::bytea, 'ipcrypt ndx by uuid round-trip');

  -- inet overload via uuid (format-preserving variants)
  SELECT is(crypto_ipcrypt_decrypt(crypto_ipcrypt_encrypt('203.0.113.9'::inet, :'det_kid'::uuid), :'det_kid'::uuid),
            '203.0.113.9'::inet, 'ipcrypt det inet by uuid round-trip');
  SELECT is(crypto_ipcrypt_pfx_decrypt(crypto_ipcrypt_pfx_encrypt('203.0.113.9'::inet, :'pfx_kid'::uuid), :'pfx_kid'::uuid),
            '203.0.113.9'::inet, 'ipcrypt pfx inet by uuid round-trip');

  RESET ROLE;
\endif
