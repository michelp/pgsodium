SET search_path TO 'public';



---- POSTGRESQL MINIMAL VERSION
SELECT cmp_ok(current_setting('server_version_num')::int, '>=', 130000, format('PostgreSQL version %s >= 13', current_setting('server_version')));



---- EXTENSION VERSION
SELECT results_eq('SELECT pgsodium.version()', $$VALUES ('3.1.9'::text)$$, 'Version of pgsodium is 3.1.9');


---- EXTENSION OBJECTS
-- Note: pay close attention to the objects schema when applicable,
-- it MUST be pgsodium.

SELECT bag_eq($$
  SELECT pg_catalog.pg_describe_object(classid, objid, 0)
  FROM pg_catalog.pg_depend
  WHERE refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
    AND refobjid = (SELECT oid FROM pg_extension WHERE extname = 'pgsodium')
    AND deptype = 'e'$$,
  $$ VALUES
    ('event trigger pgsodium_trg_mask_update'                                                                      ::text),
    ('function pgsodium.create_key(pgsodium.key_type,text,bytea,bytea,uuid,bytea,timestamp with time zone,text)'   ::text),
    ('function pgsodium.create_mask_view(oid,boolean)'                                                             ::text),
    ('function pgsodium.create_mask_view(oid,integer,boolean)'                                                     ::text),
    ('function pgsodium.crypto_aead_det_decrypt(bytea,bytea,bigint,bytea,bytea)'                                   ::text),
    ('function pgsodium.crypto_aead_det_decrypt(bytea,bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_aead_det_decrypt(bytea,bytea,uuid)'                                                 ::text),
    ('function pgsodium.crypto_aead_det_decrypt(bytea,bytea,uuid,bytea)'                                           ::text),
    ('function pgsodium.crypto_aead_det_encrypt(bytea,bytea,bigint,bytea,bytea)'                                   ::text),
    ('function pgsodium.crypto_aead_det_encrypt(bytea,bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_aead_det_encrypt(bytea,bytea,uuid)'                                                 ::text),
    ('function pgsodium.crypto_aead_det_encrypt(bytea,bytea,uuid,bytea)'                                           ::text),
    ('function pgsodium.crypto_aead_det_keygen()'                                                                  ::text),
    ('function pgsodium.crypto_aead_det_noncegen()'                                                                ::text),
    ('function pgsodium.crypto_aead_ietf_decrypt(bytea,bytea,bytea,bigint,bytea)'                                  ::text),
    ('function pgsodium.crypto_aead_ietf_decrypt(bytea,bytea,bytea,bytea)'                                         ::text),
    ('function pgsodium.crypto_aead_ietf_decrypt(bytea,bytea,bytea,uuid)'                                          ::text),
    ('function pgsodium.crypto_aead_ietf_encrypt(bytea,bytea,bytea,bigint,bytea)'                                  ::text),
    ('function pgsodium.crypto_aead_ietf_encrypt(bytea,bytea,bytea,bytea)'                                         ::text),
    ('function pgsodium.crypto_aead_ietf_encrypt(bytea,bytea,bytea,uuid)'                                          ::text),
    ('function pgsodium.crypto_aead_ietf_keygen()'                                                                 ::text),
    ('function pgsodium.crypto_aead_ietf_noncegen()'                                                               ::text),
    ('function pgsodium.crypto_auth(bytea,bigint,bytea)'                                                           ::text),
    ('function pgsodium.crypto_auth(bytea,bytea)'                                                                  ::text),
    ('function pgsodium.crypto_auth(bytea,uuid)'                                                                   ::text),
    ('function pgsodium.crypto_auth_hmacsha256(bytea,bigint,bytea)'                                                ::text),
    ('function pgsodium.crypto_auth_hmacsha256(bytea,bytea)'                                                       ::text),
    ('function pgsodium.crypto_auth_hmacsha256(bytea,uuid)'                                                        ::text),
    ('function pgsodium.crypto_auth_hmacsha256_keygen()'                                                           ::text),
    ('function pgsodium.crypto_auth_hmacsha256_verify(bytea,bytea,bigint,bytea)'                                   ::text),
    ('function pgsodium.crypto_auth_hmacsha256_verify(bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_auth_hmacsha256_verify(bytea,bytea,uuid)'                                           ::text),
    ('function pgsodium.crypto_auth_hmacsha512(bytea,bigint,bytea)'                                                ::text),
    ('function pgsodium.crypto_auth_hmacsha512(bytea,bytea)'                                                       ::text),
    ('function pgsodium.crypto_auth_hmacsha512(bytea,uuid)'                                                        ::text),
    ('function pgsodium.crypto_auth_hmacsha512_keygen()'                                                           ::text),
    ('function pgsodium.crypto_auth_hmacsha512_verify(bytea,bytea,bigint,bytea)'                                   ::text),
    ('function pgsodium.crypto_auth_hmacsha512_verify(bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_auth_hmacsha512_verify(bytea,bytea,uuid)'                                           ::text),
    ('function pgsodium.crypto_auth_keygen()'                                                                      ::text),
    ('function pgsodium.crypto_auth_verify(bytea,bytea,bigint,bytea)'                                              ::text),
    ('function pgsodium.crypto_auth_verify(bytea,bytea,bytea)'                                                     ::text),
    ('function pgsodium.crypto_auth_verify(bytea,bytea,uuid)'                                                      ::text),
    ('function pgsodium.crypto_box(bytea,bytea,bytea,bytea)'                                                       ::text),
    ('function pgsodium.crypto_box_new_keypair()'                                                                  ::text),
    ('function pgsodium.crypto_box_new_seed()'                                                                     ::text),
    ('function pgsodium.crypto_box_noncegen()'                                                                     ::text),
    ('function pgsodium.crypto_box_open(bytea,bytea,bytea,bytea)'                                                  ::text),
    ('function pgsodium.crypto_box_seal(bytea,bytea)'                                                              ::text),
    ('function pgsodium.crypto_box_seal_open(bytea,bytea,bytea)'                                                   ::text),
    ('function pgsodium.crypto_box_seed_new_keypair(bytea)'                                                        ::text),
    ('function pgsodium.crypto_cmp(text,text)'                                                                     ::text),
    ('function pgsodium.crypto_generichash(bytea,bigint,bytea)'                                                    ::text),
    ('function pgsodium.crypto_generichash(bytea,bytea)'                                                           ::text),
    ('function pgsodium.crypto_generichash(bytea,uuid)'                                                            ::text),
    ('function pgsodium.crypto_generichash_keygen()'                                                               ::text),
    ('function pgsodium.crypto_hash_sha256(bytea)'                                                                 ::text),
    ('function pgsodium.crypto_hash_sha512(bytea)'                                                                 ::text),
    ('function pgsodium.crypto_kdf_derive_from_key(bigint,bigint,bytea,bytea)'                                     ::text),
    ('function pgsodium.crypto_kdf_derive_from_key(integer,bigint,bytea,uuid)'                                     ::text),
    ('function pgsodium.crypto_kdf_keygen()'                                                                       ::text),
    ('function pgsodium.crypto_kx_client_session_keys(bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_kx_new_keypair()'                                                                   ::text),
    ('function pgsodium.crypto_kx_new_seed()'                                                                      ::text),
    ('function pgsodium.crypto_kx_seed_new_keypair(bytea)'                                                         ::text),
    ('function pgsodium.crypto_kx_server_session_keys(bytea,bytea,bytea)'                                          ::text),
    ('function pgsodium.crypto_pwhash(bytea,bytea)'                                                                ::text),
    ('function pgsodium.crypto_pwhash_saltgen()'                                                                   ::text),
    ('function pgsodium.crypto_pwhash_str(bytea)'                                                                  ::text),
    ('function pgsodium.crypto_pwhash_str_verify(bytea,bytea)'                                                     ::text),
    ('function pgsodium.crypto_secretbox(bytea,bytea,bigint,bytea)'                                                ::text),
    ('function pgsodium.crypto_secretbox(bytea,bytea,bytea)'                                                       ::text),
    ('function pgsodium.crypto_secretbox(bytea,bytea,uuid)'                                                        ::text),
    ('function pgsodium.crypto_secretbox_keygen()'                                                                 ::text),
    ('function pgsodium.crypto_secretbox_noncegen()'                                                               ::text),
    ('function pgsodium.crypto_secretbox_open(bytea,bytea,bigint,bytea)'                                           ::text),
    ('function pgsodium.crypto_secretbox_open(bytea,bytea,bytea)'                                                  ::text),
    ('function pgsodium.crypto_secretbox_open(bytea,bytea,uuid)'                                                   ::text),
    ('function pgsodium.crypto_secretstream_keygen()'                                                              ::text),
    ('function pgsodium.crypto_shorthash(bytea,bigint,bytea)'                                                      ::text),
    ('function pgsodium.crypto_shorthash(bytea,bytea)'                                                             ::text),
    ('function pgsodium.crypto_shorthash(bytea,uuid)'                                                              ::text),
    ('function pgsodium.crypto_shorthash_keygen()'                                                                 ::text),
    ('function pgsodium.crypto_sign(bytea,bytea)'                                                                  ::text),
    ('function pgsodium.crypto_sign_detached(bytea,bytea)'                                                         ::text),
    ('function pgsodium.crypto_sign_final_create(bytea,bytea)'                                                     ::text),
    ('function pgsodium.crypto_sign_final_verify(bytea,bytea,bytea)'                                               ::text),
    ('function pgsodium.crypto_sign_init()'                                                                        ::text),
    ('function pgsodium.crypto_sign_new_keypair()'                                                                 ::text),
    ('function pgsodium.crypto_sign_new_seed()'                                                                    ::text),
    ('function pgsodium.crypto_sign_open(bytea,bytea)'                                                             ::text),
    ('function pgsodium.crypto_sign_seed_new_keypair(bytea)'                                                       ::text),
    ('function pgsodium.crypto_sign_update(bytea,bytea)'                                                           ::text),
    ('function pgsodium.crypto_sign_update_agg(bytea)'                                                             ::text),
    ('function pgsodium.crypto_sign_update_agg(bytea,bytea)'                                                       ::text),
    ('function pgsodium.crypto_sign_update_agg1(bytea,bytea)'                                                      ::text),
    ('function pgsodium.crypto_sign_update_agg2(bytea,bytea,bytea)'                                                ::text),
    ('function pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)'                                            ::text),
    ('function pgsodium.crypto_signcrypt_new_keypair()'                                                            ::text),
    ('function pgsodium.crypto_signcrypt_sign_after(bytea,bytea,bytea)'                                            ::text),
    ('function pgsodium.crypto_signcrypt_sign_before(bytea,bytea,bytea,bytea,bytea)'                               ::text),
    ('function pgsodium.crypto_signcrypt_verify_after(bytea,bytea,bytea,bytea)'                                    ::text),
    ('function pgsodium.crypto_signcrypt_verify_before(bytea,bytea,bytea,bytea,bytea,bytea)'                       ::text),
    ('function pgsodium.crypto_signcrypt_verify_public(bytea,bytea,bytea,bytea,bytea,bytea)'                       ::text),
    ('function pgsodium.crypto_stream_xchacha20(bigint,bytea,bigint,bytea)'                                        ::text),
    ('function pgsodium.crypto_stream_xchacha20(bigint,bytea,bytea)'                                               ::text),
    ('function pgsodium.crypto_stream_xchacha20_keygen()'                                                          ::text),
    ('function pgsodium.crypto_stream_xchacha20_noncegen()'                                                        ::text),
    ('function pgsodium.crypto_stream_xchacha20_xor(bytea,bytea,bigint,bytea)'                                     ::text),
    ('function pgsodium.crypto_stream_xchacha20_xor(bytea,bytea,bytea)'                                            ::text),
    ('function pgsodium.crypto_stream_xchacha20_xor_ic(bytea,bytea,bigint,bigint,bytea)'                           ::text),
    ('function pgsodium.crypto_stream_xchacha20_xor_ic(bytea,bytea,bigint,bytea)'                                  ::text),
    ('function pgsodium.decrypted_columns(oid)'                                                                    ::text),
    ('function pgsodium.derive_key(bigint,integer,bytea)'                                                          ::text),
    ('function pgsodium.disable_security_label_trigger()'                                                          ::text),
    ('function pgsodium.enable_security_label_trigger()'                                                           ::text),
    ('function pgsodium.encrypted_column(oid,record)'                                                              ::text),
    ('function pgsodium.encrypted_columns(oid)'                                                                    ::text),
    ('function pgsodium.get_key_by_id(uuid)'                                                                       ::text),
    ('function pgsodium.get_key_by_name(text)'                                                                     ::text),
    ('function pgsodium.get_named_keys(text)'                                                                      ::text),
    ('function pgsodium.has_mask(regrole,text)'                                                                    ::text),
    ('function pgsodium.key_encrypt_secret_raw_key()'                                                              ::text),
    ('function pgsodium.mask_columns(oid)'                                                                         ::text),
    ('function pgsodium.mask_role(regrole,text,text)'                                                              ::text),
    ('function pgsodium.pgsodium_derive(bigint,integer,bytea)'                                                     ::text),
    ('function pgsodium.quote_assoc(text,boolean)'                                                                 ::text),
    ('function pgsodium.randombytes_buf(integer)'                                                                  ::text),
    ('function pgsodium.randombytes_buf_deterministic(integer,bytea)'                                              ::text),
    ('function pgsodium.randombytes_new_seed()'                                                                    ::text),
    ('function pgsodium.randombytes_random()'                                                                      ::text),
    ('function pgsodium.randombytes_uniform(integer)'                                                              ::text),
    ('function pgsodium.sodium_base642bin(text)'                                                                   ::text),
    ('function pgsodium.sodium_bin2base64(bytea)'                                                                  ::text),
    ('function pgsodium.trg_mask_update()'                                                                         ::text),
    ('function pgsodium.update_mask(oid,boolean)'                                                                  ::text),
    ('function pgsodium.update_masks(boolean)'                                                                     ::text),
    ('function pgsodium.version()'                                                                                 ::text),
    ('schema pgsodium_masks'                                                                                       ::text),
    ('sequence pgsodium.key_key_id_seq'                                                                            ::text),
    ('table pgsodium.key'                                                                                          ::text),
    ('type pgsodium._key_id_context'                                                                               ::text),
    ('type pgsodium.crypto_box_keypair'                                                                            ::text),
    ('type pgsodium.crypto_kx_keypair'                                                                             ::text),
    ('type pgsodium.crypto_kx_session'                                                                             ::text),
    ('type pgsodium.crypto_sign_keypair'                                                                           ::text),
    ('type pgsodium.crypto_signcrypt_keypair'                                                                      ::text),
    ('type pgsodium.crypto_signcrypt_state_key'                                                                    ::text),
    ('type pgsodium.key_status'                                                                                    ::text),
    ('type pgsodium.key_type'                                                                                      ::text),
    ('view pgsodium.decrypted_key'                                                                                 ::text),
    ('view pgsodium.mask_columns'                                                                                  ::text),
    ('view pgsodium.masking_rule'                                                                                  ::text),
    ('view pgsodium.valid_key'                                                                                     ::text),
    ('view pgsodium.seclabel'                                                                                      ::text)
  $$,
  'Check extension object list');



---- ROLES

SELECT has_role('pgsodium_keyholder');
SELECT has_role('pgsodium_keyiduser');
SELECT has_role('pgsodium_keymaker');
SELECT is_member_of( 'pgsodium_keyiduser', 'pgsodium_keyholder' );
SELECT is_member_of( 'pgsodium_keyholder', 'pgsodium_keymaker' );
SELECT is_member_of( 'pgsodium_keyiduser', 'pgsodium_keymaker' );



---- SCHEMAS

SELECT has_schema('pgsodium');
SELECT schema_owner_is('pgsodium', 'postgres');

SELECT has_schema('pgsodium_masks');
SELECT schema_owner_is('pgsodium_masks', 'postgres');




---- EVENT TRIGGERS

SELECT results_eq($q$ SELECT t.evtname
           FROM pg_catalog.pg_depend d
           JOIN pg_catalog.pg_event_trigger t ON t.oid = d.objid
           WHERE d.refclassid = $$pg_catalog.pg_extension$$::pg_catalog.regclass
             AND d.refobjid = (SELECT oid FROM pg_extension WHERE extname = $$pgsodium$$)
             AND d.deptype = $$e$$
             AND d.classid = $$pg_catalog.pg_event_trigger$$::pg_catalog.regclass
           ORDER BY 1; $q$, ARRAY[ 'pgsodium_trg_mask_update' ]::name[], $$Event trigger list is ok$$);

-- EVENT TRIGGER 'pgsodium_trg_mask_update'
SELECT results_eq($$ SELECT evtevent = 'ddl_command_end' FROM pg_catalog.pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update' $$, ARRAY[ true ], $$Trigger 'pgsodium_trg_mask_update' on event 'ddl_command_end' exists $$);
SELECT results_eq($$ SELECT evtenabled = 'O' FROM pg_catalog.pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update' $$, ARRAY[ true ], $$Trigger 'pgsodium_trg_mask_update' enabled status ok $$);
SELECT results_eq($$ SELECT pg_catalog.unnest(evttags) FROM pg_catalog.pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update' ORDER BY 1 $$, ARRAY[ 'ALTER TABLE','SECURITY LABEL' ]::text[] collate "C", $$Trigger 'pgsodium_trg_mask_update' tags are ok$$);
SELECT results_eq($$ SELECT pg_catalog.pg_get_userbyid(evtowner) = 'postgres' FROM pg_catalog.pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update' $$, ARRAY[ true ], $$Trigger 'pgsodium_trg_mask_update' owner is 'postgres'$$);
SELECT results_eq($$ SELECT evtfoid = 'pgsodium.trg_mask_update'::regproc FROM pg_catalog.pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update' $$, ARRAY[ true ], $$Trigger 'pgsodium_trg_mask_update' function is 'pgsodium.trg_mask_update'$$);



---- TABLES

SELECT tables_are('pgsodium', ARRAY[
    'key'
]);

---- TABLE key

-- cols of relation key
SELECT columns_are('pgsodium'::name, 'key'::name, ARRAY[
  'id',
  'status',
  'created',
  'expires',
  'key_type',
  'key_id',
  'key_context',
  'name',
  'associated_data',
  'raw_key',
  'raw_key_nonce',
  'parent_key',
  'comment',
  'user_data'
]::name[]);

SELECT has_column(       'pgsodium', 'key', 'id'             , 'has column key.id');
SELECT col_type_is(      'pgsodium', 'key', 'id'             , 'uuid', 'type of column key.id is uuid');
SELECT col_not_null(     'pgsodium', 'key', 'id'             , 'col_not_null( key.id )');
SELECT col_has_default(  'pgsodium', 'key', 'id'             , 'col_has_default( key.id )');
SELECT col_default_is(   'pgsodium', 'key', 'id'             , 'gen_random_uuid()', 'default definition of key.id');

SELECT has_column(       'pgsodium', 'key', 'status'         , 'has column key.status');
SELECT col_type_is(      'pgsodium', 'key', 'status'         , 'pgsodium.key_status', 'type of column key.status is pgsodium.key_status');
SELECT col_is_null(      'pgsodium', 'key', 'status'         , 'col_is_null( key.status )');
SELECT col_has_default(  'pgsodium', 'key', 'status'         , 'col_has_default( key.status )');
SELECT col_default_is(   'pgsodium', 'key', 'status'         , 'valid'::pgsodium.key_status, 'default definition of key.status');

SELECT has_column(       'pgsodium', 'key', 'created'        , 'has column key.created');
SELECT col_type_is(      'pgsodium', 'key', 'created'        , 'timestamp with time zone', 'type of column key.created is timestamp with time zone');
SELECT col_not_null(     'pgsodium', 'key', 'created'        , 'col_not_null( key.created )');
SELECT col_has_default(  'pgsodium', 'key', 'created'        , 'col_has_default( key.created )');
SELECT col_default_is(   'pgsodium', 'key', 'created'        , 'CURRENT_TIMESTAMP', 'default definition of key.created');

SELECT has_column(       'pgsodium', 'key', 'expires'        , 'has column key.expires');
SELECT col_type_is(      'pgsodium', 'key', 'expires'        , 'timestamp with time zone', 'type of column key.expires is timestamp with time zone');
SELECT col_is_null(      'pgsodium', 'key', 'expires'        , 'col_is_null( key.expires )');
SELECT col_hasnt_default('pgsodium', 'key', 'expires'        , 'col_hasnt_default( key.expires )');

SELECT has_column(       'pgsodium', 'key', 'key_type'       , 'has column key.key_type');
SELECT col_type_is(      'pgsodium', 'key', 'key_type'       , 'pgsodium.key_type', 'type of column key.key_type is pgsodium.key_type');
SELECT col_is_null(      'pgsodium', 'key', 'key_type'       , 'col_is_null( key.key_type )');
SELECT col_hasnt_default('pgsodium', 'key', 'key_type'       , 'col_hasnt_default( key.key_type )');

SELECT has_column(       'pgsodium', 'key', 'key_id'         , 'has column key.key_id');
SELECT col_type_is(      'pgsodium', 'key', 'key_id'         , 'bigint', 'type of column key.key_id is bigint');
SELECT col_is_null(      'pgsodium', 'key', 'key_id'         , 'col_is_null( key.key_id )');
SELECT col_has_default(  'pgsodium', 'key', 'key_id'         , 'col_has_default( key.key_id )');
SELECT col_default_is(   'pgsodium', 'key', 'key_id'         , 'nextval(''pgsodium.key_key_id_seq''::regclass)', 'default definition of key.key_id');

SELECT has_column(       'pgsodium', 'key', 'key_context'    , 'has column key.key_context');
SELECT col_type_is(      'pgsodium', 'key', 'key_context'    , 'bytea', 'type of column key.key_context is bytea');
SELECT col_is_null(      'pgsodium', 'key', 'key_context'    , 'col_is_null( key.key_context )');
SELECT col_has_default(  'pgsodium', 'key', 'key_context'    , 'col_has_default( key.key_context )');
SELECT col_default_is(   'pgsodium', 'key', 'key_context'    , '\x7067736f6469756d'::bytea, 'default definition of key.key_context');

SELECT has_column(       'pgsodium', 'key', 'name'           , 'has column key.name');
SELECT col_type_is(      'pgsodium', 'key', 'name'           , 'text', 'type of column key.name is text');
SELECT col_is_null(      'pgsodium', 'key', 'name'           , 'col_is_null( key.name )');
SELECT col_hasnt_default('pgsodium', 'key', 'name'           , 'col_hasnt_default( key.name )');

SELECT has_column(       'pgsodium', 'key', 'associated_data', 'has column key.associated_data');
SELECT col_type_is(      'pgsodium', 'key', 'associated_data', 'text', 'type of column key.associated_data is text');
SELECT col_is_null(      'pgsodium', 'key', 'associated_data', 'col_is_null( key.associated_data )');
SELECT col_has_default(  'pgsodium', 'key', 'associated_data', 'col_has_default( key.associated_data )');
SELECT col_default_is(   'pgsodium', 'key', 'associated_data', 'associated'::text, 'default definition of key.associated_data');

SELECT has_column(       'pgsodium', 'key', 'raw_key'        , 'has column key.raw_key');
SELECT col_type_is(      'pgsodium', 'key', 'raw_key'        , 'bytea', 'type of column key.raw_key is bytea');
SELECT col_is_null(      'pgsodium', 'key', 'raw_key'        , 'col_is_null( key.raw_key )');
SELECT col_hasnt_default('pgsodium', 'key', 'raw_key'        , 'col_hasnt_default( key.raw_key )');

SELECT has_column(       'pgsodium', 'key', 'raw_key_nonce'  , 'has column key.raw_key_nonce');
SELECT col_type_is(      'pgsodium', 'key', 'raw_key_nonce'  , 'bytea', 'type of column key.raw_key_nonce is bytea');
SELECT col_is_null(      'pgsodium', 'key', 'raw_key_nonce'  , 'col_is_null( key.raw_key_nonce )');
SELECT col_hasnt_default('pgsodium', 'key', 'raw_key_nonce'  , 'col_hasnt_default( key.raw_key_nonce )');

SELECT has_column(       'pgsodium', 'key', 'parent_key'     , 'has column key.parent_key');
SELECT col_type_is(      'pgsodium', 'key', 'parent_key'     , 'uuid', 'type of column key.parent_key is uuid');
SELECT col_is_null(      'pgsodium', 'key', 'parent_key'     , 'col_is_null( key.parent_key )');
SELECT col_hasnt_default('pgsodium', 'key', 'parent_key'     , 'col_hasnt_default( key.parent_key )');

SELECT has_column(       'pgsodium', 'key', 'comment'        , 'has column key.comment');
SELECT col_type_is(      'pgsodium', 'key', 'comment'        , 'text', 'type of column key.comment is text');
SELECT col_is_null(      'pgsodium', 'key', 'comment'        , 'col_is_null( key.comment )');
SELECT col_hasnt_default('pgsodium', 'key', 'comment'        , 'col_hasnt_default( key.comment )');

SELECT has_column(       'pgsodium', 'key', 'user_data'      , 'has column key.user_data');
SELECT col_type_is(      'pgsodium', 'key', 'user_data'      , 'text', 'type of column key.user_data is text');
SELECT col_is_null(      'pgsodium', 'key', 'user_data'      , 'col_is_null( key.user_data )');
SELECT col_hasnt_default('pgsodium', 'key', 'user_data'      , 'col_hasnt_default( key.user_data )');

SELECT has_pk('pgsodium', 'key', 'table key has a PK');

-- Constraints on table key
SELECT results_eq(
  $q$ SELECT c.conname
  FROM pg_catalog.pg_constraint c
  JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
  JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
  WHERE n.nspname = 'pgsodium' AND r.relname = 'key'
  ORDER BY c.contype, c.conname $q$,
  ARRAY[
    'key_key_context_check',
    'pgsodium_raw',
    'key_parent_key_fkey',
    'key_pkey',
    'pgsodium_key_unique_name'
  ]::name[],
  $$Event trigger list is ok$$);

-- constraint 'key_key_context_check' on 'key'
SELECT is(pg_catalog.pg_get_constraintdef(c.oid, true),'CHECK (length(key_context) = 8)', $$Definition of constraint 'key_key_context_check'$$)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.conname = 'key_key_context_check';

-- constraint 'pgsodium_raw' on 'key'
SELECT is(pg_catalog.pg_get_constraintdef(c.oid, true),'CHECK (
CASE
    WHEN raw_key IS NOT NULL THEN key_id IS NULL AND key_context IS NULL AND parent_key IS NOT NULL
    ELSE key_id IS NOT NULL AND key_context IS NOT NULL AND parent_key IS NULL
END)', $$Definition of constraint 'pgsodium_raw'$$)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.conname = 'pgsodium_raw';

-- constraint 'key_parent_key_fkey' on 'key'
SELECT is(pg_catalog.pg_get_constraintdef(c.oid, true),'FOREIGN KEY (parent_key) REFERENCES pgsodium.key(id)', $$Definition of constraint 'key_parent_key_fkey'$$)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.conname = 'key_parent_key_fkey';

-- constraint 'key_pkey' on 'key'
SELECT is(pg_catalog.pg_get_constraintdef(c.oid, true),'PRIMARY KEY (id)', $$Definition of constraint 'key_pkey'$$)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.conname = 'key_pkey';

-- constraint 'pgsodium_key_unique_name' on 'key'
SELECT is(pg_catalog.pg_get_constraintdef(c.oid, true),'UNIQUE (name)', $$Definition of constraint 'pgsodium_key_unique_name'$$)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON c.conrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.conname = 'pgsodium_key_unique_name';

-- indexes of table key
SELECT indexes_are('pgsodium'::name, 'key'::name, ARRAY[
  'key_key_id_key_context_key_type_idx',
  'key_pkey',
  'key_status_idx',
  'key_status_idx1',
  'pgsodium_key_unique_name'
]::name[]);

-- index 'key_key_id_key_context_key_type_idx' on key
SELECT is(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true),'CREATE UNIQUE INDEX key_key_id_key_context_key_type_idx ON pgsodium.key USING btree (key_id, key_context, key_type)', $$Definition of index 'key_key_id_key_context_key_type_idx'$$)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_index i ON c.oid = i.indexrelid
JOIN pg_catalog.pg_class r ON i.indrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.relname = 'key_key_id_key_context_key_type_idx';

-- index 'key_pkey' on key
SELECT is(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true),'CREATE UNIQUE INDEX key_pkey ON pgsodium.key USING btree (id)', $$Definition of index 'key_pkey'$$)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_index i ON c.oid = i.indexrelid
JOIN pg_catalog.pg_class r ON i.indrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.relname = 'key_pkey';
SELECT index_is_primary( 'pgsodium'::name, 'key'::name, 'key_pkey'::name);

-- index 'key_status_idx' on key
SELECT is(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true),'CREATE INDEX key_status_idx ON pgsodium.key USING btree (status) WHERE status = ANY (ARRAY[''valid''::pgsodium.key_status, ''default''::pgsodium.key_status])', $$Definition of index 'key_status_idx'$$)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_index i ON c.oid = i.indexrelid
JOIN pg_catalog.pg_class r ON i.indrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.relname = 'key_status_idx';

-- index 'key_status_idx1' on key
SELECT is(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true),'CREATE UNIQUE INDEX key_status_idx1 ON pgsodium.key USING btree (status) WHERE status = ''default''::pgsodium.key_status', $$Definition of index 'key_status_idx1'$$)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_index i ON c.oid = i.indexrelid
JOIN pg_catalog.pg_class r ON i.indrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.relname = 'key_status_idx1';

-- index 'pgsodium_key_unique_name' on key
SELECT is(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true),'CREATE UNIQUE INDEX pgsodium_key_unique_name ON pgsodium.key USING btree (name)', $$Definition of index 'pgsodium_key_unique_name'$$)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_index i ON c.oid = i.indexrelid
JOIN pg_catalog.pg_class r ON i.indrelid = r.oid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'pgsodium' AND r.relname = 'key' AND c.relname = 'pgsodium_key_unique_name';

-- triggers of relation key
SELECT triggers_are('pgsodium', 'key', ARRAY[
    'key_encrypt_secret_trigger_raw_key'
]);

SELECT has_trigger( 'pgsodium', 'key', 'key_encrypt_secret_trigger_raw_key'::name);
SELECT trigger_is(  'pgsodium', 'key', 'key_encrypt_secret_trigger_raw_key'::name, 'pgsodium', 'key_encrypt_secret_raw_key');

-- owner of table key
SELECT table_owner_is('pgsodium'::name, 'key'::name, 'postgres'::name);


-- privs of relation key
SELECT table_privs_are('pgsodium'::name, 'key'::name, 'pgsodium_keymaker'         ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'key'::name, 'postgres'                  ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'key'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keymaker','postgres');



---- VIEWS

SELECT views_are('pgsodium', ARRAY[
    'decrypted_key',
    'mask_columns',
    'masking_rule',
    'valid_key',
    'seclabel'
]);

---- VIEW decrypted_key

-- cols of relation decrypted_key
SELECT columns_are('pgsodium'::name, 'decrypted_key'::name, ARRAY[
  'id',
  'status',
  'created',
  'expires',
  'key_type',
  'key_id',
  'key_context',
  'name',
  'associated_data',
  'raw_key',
  'decrypted_raw_key',
  'raw_key_nonce',
  'parent_key',
  'comment'
]::name[]);

SELECT has_column(       'pgsodium', 'decrypted_key', 'id'             , 'has column decrypted_key.id');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'id'             , 'uuid', 'type of column decrypted_key.id is uuid');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'id'             , 'col_is_null( decrypted_key.id )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'id'             , 'col_hasnt_default( decrypted_key.id )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'status'         , 'has column decrypted_key.status');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'status'         , 'pgsodium.key_status', 'type of column decrypted_key.status is pgsodium.key_status');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'status'         , 'col_is_null( decrypted_key.status )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'status'         , 'col_hasnt_default( decrypted_key.status )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'created'        , 'has column decrypted_key.created');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'created'        , 'timestamp with time zone', 'type of column decrypted_key.created is timestamp with time zone');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'created'        , 'col_is_null( decrypted_key.created )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'created'        , 'col_hasnt_default( decrypted_key.created )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'expires'        , 'has column decrypted_key.expires');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'expires'        , 'timestamp with time zone', 'type of column decrypted_key.expires is timestamp with time zone');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'expires'        , 'col_is_null( decrypted_key.expires )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'expires'        , 'col_hasnt_default( decrypted_key.expires )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'key_type'       , 'has column decrypted_key.key_type');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'key_type'       , 'pgsodium.key_type', 'type of column decrypted_key.key_type is pgsodium.key_type');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'key_type'       , 'col_is_null( decrypted_key.key_type )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'key_type'       , 'col_hasnt_default( decrypted_key.key_type )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'key_id'         , 'has column decrypted_key.key_id');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'key_id'         , 'bigint', 'type of column decrypted_key.key_id is bigint');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'key_id'         , 'col_is_null( decrypted_key.key_id )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'key_id'         , 'col_hasnt_default( decrypted_key.key_id )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'key_context'    , 'has column decrypted_key.key_context');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'key_context'    , 'bytea', 'type of column decrypted_key.key_context is bytea');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'key_context'    , 'col_is_null( decrypted_key.key_context )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'key_context'    , 'col_hasnt_default( decrypted_key.key_context )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'name'           , 'has column decrypted_key.name');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'name'           , 'text', 'type of column decrypted_key.name is text');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'name'           , 'col_is_null( decrypted_key.name )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'name'           , 'col_hasnt_default( decrypted_key.name )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'associated_data', 'has column decrypted_key.associated_data');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'associated_data', 'text', 'type of column decrypted_key.associated_data is text');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'associated_data', 'col_is_null( decrypted_key.associated_data )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'associated_data', 'col_hasnt_default( decrypted_key.associated_data )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'raw_key'        , 'has column decrypted_key.raw_key');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'raw_key'        , 'bytea', 'type of column decrypted_key.raw_key is bytea');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'raw_key'        , 'col_is_null( decrypted_key.raw_key )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'raw_key'        , 'col_hasnt_default( decrypted_key.raw_key )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'decrypted_raw_key', 'has column decrypted_key.decrypted_raw_key');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'decrypted_raw_key', 'bytea', 'type of column decrypted_key.decrypted_raw_key is bytea');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'decrypted_raw_key', 'col_is_null( decrypted_key.decrypted_raw_key )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'decrypted_raw_key', 'col_hasnt_default( decrypted_key.decrypted_raw_key )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'raw_key_nonce'  , 'has column decrypted_key.raw_key_nonce');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'raw_key_nonce'  , 'bytea', 'type of column decrypted_key.raw_key_nonce is bytea');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'raw_key_nonce'  , 'col_is_null( decrypted_key.raw_key_nonce )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'raw_key_nonce'  , 'col_hasnt_default( decrypted_key.raw_key_nonce )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'parent_key'     , 'has column decrypted_key.parent_key');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'parent_key'     , 'uuid', 'type of column decrypted_key.parent_key is uuid');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'parent_key'     , 'col_is_null( decrypted_key.parent_key )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'parent_key'     , 'col_hasnt_default( decrypted_key.parent_key )');

SELECT has_column(       'pgsodium', 'decrypted_key', 'comment'        , 'has column decrypted_key.comment');
SELECT col_type_is(      'pgsodium', 'decrypted_key', 'comment'        , 'text', 'type of column decrypted_key.comment is text');
SELECT col_is_null(      'pgsodium', 'decrypted_key', 'comment'        , 'col_is_null( decrypted_key.comment )');
SELECT col_hasnt_default('pgsodium', 'decrypted_key', 'comment'        , 'col_hasnt_default( decrypted_key.comment )');


-- owner of view decrypted_key
SELECT view_owner_is('pgsodium'::name, 'decrypted_key'::name, 'postgres'::name);


-- privs of relation decrypted_key
SELECT table_privs_are('pgsodium'::name, 'decrypted_key'::name, 'pgsodium_keyholder'        ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'decrypted_key'::name, 'pgsodium_keymaker'         ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'decrypted_key'::name, 'postgres'                  ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'decrypted_key'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keyholder','pgsodium_keymaker','postgres');
---- VIEW mask_columns

-- cols of relation mask_columns
SELECT columns_are('pgsodium'::name, 'mask_columns'::name, ARRAY[
  'attname',
  'attrelid',
  'key_id',
  'key_id_column',
  'associated_columns',
  'nonce_column',
  'format_type'
]::name[]);

SELECT has_column(       'pgsodium', 'mask_columns', 'attname'        , 'has column mask_columns.attname');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'attname'        , 'name', 'type of column mask_columns.attname is name');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'attname'        , 'col_is_null( mask_columns.attname )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'attname'        , 'col_hasnt_default( mask_columns.attname )');

SELECT has_column(       'pgsodium', 'mask_columns', 'attrelid'       , 'has column mask_columns.attrelid');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'attrelid'       , 'oid', 'type of column mask_columns.attrelid is oid');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'attrelid'       , 'col_is_null( mask_columns.attrelid )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'attrelid'       , 'col_hasnt_default( mask_columns.attrelid )');

SELECT has_column(       'pgsodium', 'mask_columns', 'key_id'         , 'has column mask_columns.key_id');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'key_id'         , 'text', 'type of column mask_columns.key_id is text');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'key_id'         , 'col_is_null( mask_columns.key_id )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'key_id'         , 'col_hasnt_default( mask_columns.key_id )');

SELECT has_column(       'pgsodium', 'mask_columns', 'key_id_column'  , 'has column mask_columns.key_id_column');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'key_id_column'  , 'text', 'type of column mask_columns.key_id_column is text');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'key_id_column'  , 'col_is_null( mask_columns.key_id_column )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'key_id_column'  , 'col_hasnt_default( mask_columns.key_id_column )');

SELECT has_column(       'pgsodium', 'mask_columns', 'associated_columns', 'has column mask_columns.associated_columns');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'associated_columns', 'text', 'type of column mask_columns.associated_columns is text');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'associated_columns', 'col_is_null( mask_columns.associated_columns )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'associated_columns', 'col_hasnt_default( mask_columns.associated_columns )');

SELECT has_column(       'pgsodium', 'mask_columns', 'nonce_column'   , 'has column mask_columns.nonce_column');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'nonce_column'   , 'text', 'type of column mask_columns.nonce_column is text');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'nonce_column'   , 'col_is_null( mask_columns.nonce_column )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'nonce_column'   , 'col_hasnt_default( mask_columns.nonce_column )');

SELECT has_column(       'pgsodium', 'mask_columns', 'format_type'    , 'has column mask_columns.format_type');
SELECT col_type_is(      'pgsodium', 'mask_columns', 'format_type'    , 'text', 'type of column mask_columns.format_type is text');
SELECT col_is_null(      'pgsodium', 'mask_columns', 'format_type'    , 'col_is_null( mask_columns.format_type )');
SELECT col_hasnt_default('pgsodium', 'mask_columns', 'format_type'    , 'col_hasnt_default( mask_columns.format_type )');


-- owner of view mask_columns
SELECT view_owner_is('pgsodium'::name, 'mask_columns'::name, 'postgres'::name);


-- privs of relation mask_columns
SELECT table_privs_are('pgsodium'::name, 'mask_columns'::name, 'pgsodium_keyholder'        ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'mask_columns'::name, 'pgsodium_keymaker'         ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'mask_columns'::name, 'postgres'                  ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'mask_columns'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keyholder','pgsodium_keymaker','postgres');
---- VIEW masking_rule

-- cols of relation masking_rule
SELECT columns_are('pgsodium'::name, 'masking_rule'::name, ARRAY[
  'attrelid',
  'attnum',
  'relnamespace',
  'relname',
  'attname',
  'format_type',
  'col_description',
  'key_id_column',
  'key_id',
  'associated_columns',
  'nonce_column',
  'view_name',
  'priority',
  'security_invoker'
]::name[]);

SELECT has_column(       'pgsodium', 'masking_rule', 'attrelid'       , 'has column masking_rule.attrelid');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'attrelid'       , 'oid', 'type of column masking_rule.attrelid is oid');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'attrelid'       , 'col_is_null( masking_rule.attrelid )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'attrelid'       , 'col_hasnt_default( masking_rule.attrelid )');

SELECT has_column(       'pgsodium', 'masking_rule', 'attnum'         , 'has column masking_rule.attnum');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'attnum'         , 'integer', 'type of column masking_rule.attnum is integer');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'attnum'         , 'col_is_null( masking_rule.attnum )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'attnum'         , 'col_hasnt_default( masking_rule.attnum )');

SELECT has_column(       'pgsodium', 'masking_rule', 'relnamespace'   , 'has column masking_rule.relnamespace');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'relnamespace'   , 'regnamespace', 'type of column masking_rule.relnamespace is regnamespace');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'relnamespace'   , 'col_is_null( masking_rule.relnamespace )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'relnamespace'   , 'col_hasnt_default( masking_rule.relnamespace )');

SELECT has_column(       'pgsodium', 'masking_rule', 'relname'        , 'has column masking_rule.relname');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'relname'        , 'name', 'type of column masking_rule.relname is name');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'relname'        , 'col_is_null( masking_rule.relname )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'relname'        , 'col_hasnt_default( masking_rule.relname )');

SELECT has_column(       'pgsodium', 'masking_rule', 'attname'        , 'has column masking_rule.attname');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'attname'        , 'name', 'type of column masking_rule.attname is name');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'attname'        , 'col_is_null( masking_rule.attname )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'attname'        , 'col_hasnt_default( masking_rule.attname )');

SELECT has_column(       'pgsodium', 'masking_rule', 'format_type'    , 'has column masking_rule.format_type');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'format_type'    , 'text', 'type of column masking_rule.format_type is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'format_type'    , 'col_is_null( masking_rule.format_type )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'format_type'    , 'col_hasnt_default( masking_rule.format_type )');

SELECT has_column(       'pgsodium', 'masking_rule', 'col_description', 'has column masking_rule.col_description');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'col_description', 'text', 'type of column masking_rule.col_description is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'col_description', 'col_is_null( masking_rule.col_description )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'col_description', 'col_hasnt_default( masking_rule.col_description )');

SELECT has_column(       'pgsodium', 'masking_rule', 'key_id_column'  , 'has column masking_rule.key_id_column');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'key_id_column'  , 'text', 'type of column masking_rule.key_id_column is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'key_id_column'  , 'col_is_null( masking_rule.key_id_column )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'key_id_column'  , 'col_hasnt_default( masking_rule.key_id_column )');

SELECT has_column(       'pgsodium', 'masking_rule', 'key_id'         , 'has column masking_rule.key_id');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'key_id'         , 'text', 'type of column masking_rule.key_id is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'key_id'         , 'col_is_null( masking_rule.key_id )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'key_id'         , 'col_hasnt_default( masking_rule.key_id )');

SELECT has_column(       'pgsodium', 'masking_rule', 'associated_columns', 'has column masking_rule.associated_columns');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'associated_columns', 'text', 'type of column masking_rule.associated_columns is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'associated_columns', 'col_is_null( masking_rule.associated_columns )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'associated_columns', 'col_hasnt_default( masking_rule.associated_columns )');

SELECT has_column(       'pgsodium', 'masking_rule', 'nonce_column'   , 'has column masking_rule.nonce_column');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'nonce_column'   , 'text', 'type of column masking_rule.nonce_column is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'nonce_column'   , 'col_is_null( masking_rule.nonce_column )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'nonce_column'   , 'col_hasnt_default( masking_rule.nonce_column )');

SELECT has_column(       'pgsodium', 'masking_rule', 'view_name'      , 'has column masking_rule.view_name');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'view_name'      , 'text', 'type of column masking_rule.view_name is text');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'view_name'      , 'col_is_null( masking_rule.view_name )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'view_name'      , 'col_hasnt_default( masking_rule.view_name )');

SELECT has_column(       'pgsodium', 'masking_rule', 'priority'       , 'has column masking_rule.priority');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'priority'       , 'integer', 'type of column masking_rule.priority is integer');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'priority'       , 'col_is_null( masking_rule.priority )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'priority'       , 'col_hasnt_default( masking_rule.priority )');

SELECT has_column(       'pgsodium', 'masking_rule', 'security_invoker', 'has column masking_rule.security_invoker');
SELECT col_type_is(      'pgsodium', 'masking_rule', 'security_invoker', 'boolean', 'type of column masking_rule.security_invoker is boolean');
SELECT col_is_null(      'pgsodium', 'masking_rule', 'security_invoker', 'col_is_null( masking_rule.security_invoker )');
SELECT col_hasnt_default('pgsodium', 'masking_rule', 'security_invoker', 'col_hasnt_default( masking_rule.security_invoker )');


-- owner of view masking_rule
SELECT view_owner_is('pgsodium'::name, 'masking_rule'::name, 'postgres'::name);


-- privs of relation masking_rule
SELECT table_privs_are('pgsodium'::name, 'masking_rule'::name, 'pgsodium_keyholder'        ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'masking_rule'::name, 'pgsodium_keymaker'         ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'masking_rule'::name, 'postgres'                  ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'masking_rule'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keyholder','pgsodium_keymaker','postgres');
---- VIEW valid_key

-- cols of relation valid_key
SELECT columns_are('pgsodium'::name, 'valid_key'::name, ARRAY[
  'id',
  'name',
  'status',
  'key_type',
  'key_id',
  'key_context',
  'created',
  'expires',
  'associated_data'
]::name[]);

SELECT has_column(       'pgsodium', 'valid_key', 'id'             , 'has column valid_key.id');
SELECT col_type_is(      'pgsodium', 'valid_key', 'id'             , 'uuid', 'type of column valid_key.id is uuid');
SELECT col_is_null(      'pgsodium', 'valid_key', 'id'             , 'col_is_null( valid_key.id )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'id'             , 'col_hasnt_default( valid_key.id )');

SELECT has_column(       'pgsodium', 'valid_key', 'name'           , 'has column valid_key.name');
SELECT col_type_is(      'pgsodium', 'valid_key', 'name'           , 'text', 'type of column valid_key.name is text');
SELECT col_is_null(      'pgsodium', 'valid_key', 'name'           , 'col_is_null( valid_key.name )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'name'           , 'col_hasnt_default( valid_key.name )');

SELECT has_column(       'pgsodium', 'valid_key', 'status'         , 'has column valid_key.status');
SELECT col_type_is(      'pgsodium', 'valid_key', 'status'         , 'pgsodium.key_status', 'type of column valid_key.status is pgsodium.key_status');
SELECT col_is_null(      'pgsodium', 'valid_key', 'status'         , 'col_is_null( valid_key.status )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'status'         , 'col_hasnt_default( valid_key.status )');

SELECT has_column(       'pgsodium', 'valid_key', 'key_type'       , 'has column valid_key.key_type');
SELECT col_type_is(      'pgsodium', 'valid_key', 'key_type'       , 'pgsodium.key_type', 'type of column valid_key.key_type is pgsodium.key_type');
SELECT col_is_null(      'pgsodium', 'valid_key', 'key_type'       , 'col_is_null( valid_key.key_type )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'key_type'       , 'col_hasnt_default( valid_key.key_type )');

SELECT has_column(       'pgsodium', 'valid_key', 'key_id'         , 'has column valid_key.key_id');
SELECT col_type_is(      'pgsodium', 'valid_key', 'key_id'         , 'bigint', 'type of column valid_key.key_id is bigint');
SELECT col_is_null(      'pgsodium', 'valid_key', 'key_id'         , 'col_is_null( valid_key.key_id )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'key_id'         , 'col_hasnt_default( valid_key.key_id )');

SELECT has_column(       'pgsodium', 'valid_key', 'key_context'    , 'has column valid_key.key_context');
SELECT col_type_is(      'pgsodium', 'valid_key', 'key_context'    , 'bytea', 'type of column valid_key.key_context is bytea');
SELECT col_is_null(      'pgsodium', 'valid_key', 'key_context'    , 'col_is_null( valid_key.key_context )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'key_context'    , 'col_hasnt_default( valid_key.key_context )');

SELECT has_column(       'pgsodium', 'valid_key', 'created'        , 'has column valid_key.created');
SELECT col_type_is(      'pgsodium', 'valid_key', 'created'        , 'timestamp with time zone', 'type of column valid_key.created is timestamp with time zone');
SELECT col_is_null(      'pgsodium', 'valid_key', 'created'        , 'col_is_null( valid_key.created )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'created'        , 'col_hasnt_default( valid_key.created )');

SELECT has_column(       'pgsodium', 'valid_key', 'expires'        , 'has column valid_key.expires');
SELECT col_type_is(      'pgsodium', 'valid_key', 'expires'        , 'timestamp with time zone', 'type of column valid_key.expires is timestamp with time zone');
SELECT col_is_null(      'pgsodium', 'valid_key', 'expires'        , 'col_is_null( valid_key.expires )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'expires'        , 'col_hasnt_default( valid_key.expires )');

SELECT has_column(       'pgsodium', 'valid_key', 'associated_data', 'has column valid_key.associated_data');
SELECT col_type_is(      'pgsodium', 'valid_key', 'associated_data', 'text', 'type of column valid_key.associated_data is text');
SELECT col_is_null(      'pgsodium', 'valid_key', 'associated_data', 'col_is_null( valid_key.associated_data )');
SELECT col_hasnt_default('pgsodium', 'valid_key', 'associated_data', 'col_hasnt_default( valid_key.associated_data )');


-- owner of view valid_key
SELECT view_owner_is('pgsodium'::name, 'valid_key'::name, 'postgres'::name);


-- privs of relation valid_key
SELECT table_privs_are('pgsodium'::name, 'valid_key'::name, 'pgsodium_keyholder'        ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'valid_key'::name, 'pgsodium_keyiduser'        ::name, '{SELECT}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'valid_key'::name, 'pgsodium_keymaker'         ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'valid_key'::name, 'postgres'                  ::name, '{DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE}'::text[]);
SELECT table_privs_are('pgsodium'::name, 'valid_key'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keyholder','pgsodium_keyiduser','pgsodium_keymaker','postgres');



---- SEQUENCES

SELECT sequences_are('pgsodium', ARRAY[
    'key_key_id_seq'
]);

---- SEQUENCE key_key_id_seq

-- owner of sequence key_key_id_seq
SELECT sequence_owner_is('pgsodium'::name, 'key_key_id_seq'::name, 'postgres'::name);


-- privs of relation key_key_id_seq
SELECT sequence_privs_are('pgsodium'::name, 'key_key_id_seq'::name, 'pgsodium_keymaker'         ::name, '{SELECT,UPDATE,USAGE}'::text[]);
SELECT sequence_privs_are('pgsodium'::name, 'key_key_id_seq'::name, 'postgres'                  ::name, '{SELECT,UPDATE,USAGE}'::text[]);
SELECT sequence_privs_are('pgsodium'::name, 'key_key_id_seq'::name, rolname,                    '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname NOT IN ('pg_read_all_data','pg_write_all_data','pgsodium_keymaker','postgres');



---- FUNCTIONS

SELECT functions_are('pgsodium', ARRAY[
    'create_key',
    'create_mask_view',
    'crypto_aead_det_decrypt',
    'crypto_aead_det_encrypt',
    'crypto_aead_det_keygen',
    'crypto_aead_det_noncegen',
    'crypto_aead_ietf_decrypt',
    'crypto_aead_ietf_encrypt',
    'crypto_aead_ietf_keygen',
    'crypto_aead_ietf_noncegen',
    'crypto_auth',
    'crypto_auth_hmacsha256',
    'crypto_auth_hmacsha256_keygen',
    'crypto_auth_hmacsha256_verify',
    'crypto_auth_hmacsha512',
    'crypto_auth_hmacsha512_keygen',
    'crypto_auth_hmacsha512_verify',
    'crypto_auth_keygen',
    'crypto_auth_verify',
    'crypto_box',
    'crypto_box_new_keypair',
    'crypto_box_new_seed',
    'crypto_box_noncegen',
    'crypto_box_open',
    'crypto_box_seal',
    'crypto_box_seal_open',
    'crypto_box_seed_new_keypair',
    'crypto_cmp',
    'crypto_generichash',
    'crypto_generichash_keygen',
    'crypto_hash_sha256',
    'crypto_hash_sha512',
    'crypto_kdf_derive_from_key',
    'crypto_kdf_keygen',
    'crypto_kx_client_session_keys',
    'crypto_kx_new_keypair',
    'crypto_kx_new_seed',
    'crypto_kx_seed_new_keypair',
    'crypto_kx_server_session_keys',
    'crypto_pwhash',
    'crypto_pwhash_saltgen',
    'crypto_pwhash_str',
    'crypto_pwhash_str_verify',
    'crypto_secretbox',
    'crypto_secretbox_keygen',
    'crypto_secretbox_noncegen',
    'crypto_secretbox_open',
    'crypto_secretstream_keygen',
    'crypto_shorthash',
    'crypto_shorthash_keygen',
    'crypto_sign',
    'crypto_sign_detached',
    'crypto_sign_final_create',
    'crypto_sign_final_verify',
    'crypto_sign_init',
    'crypto_sign_new_keypair',
    'crypto_sign_new_seed',
    'crypto_sign_open',
    'crypto_sign_seed_new_keypair',
    'crypto_sign_update',
    'crypto_sign_update_agg',
    'crypto_sign_update_agg1',
    'crypto_sign_update_agg2',
    'crypto_sign_verify_detached',
    'crypto_signcrypt_new_keypair',
    'crypto_signcrypt_sign_after',
    'crypto_signcrypt_sign_before',
    'crypto_signcrypt_verify_after',
    'crypto_signcrypt_verify_before',
    'crypto_signcrypt_verify_public',
    'crypto_stream_xchacha20',
    'crypto_stream_xchacha20_keygen',
    'crypto_stream_xchacha20_noncegen',
    'crypto_stream_xchacha20_xor',
    'crypto_stream_xchacha20_xor_ic',
    'decrypted_columns',
    'derive_key',
    'disable_security_label_trigger',
    'enable_security_label_trigger',
    'encrypted_column',
    'encrypted_columns',
    'get_key_by_id',
    'get_key_by_name',
    'get_named_keys',
    'has_mask',
    'key_encrypt_secret_raw_key',
    'mask_columns',
    'mask_role',
    'pgsodium_derive',
    'quote_assoc',
    'randombytes_buf',
    'randombytes_buf_deterministic',
    'randombytes_new_seed',
    'randombytes_random',
    'randombytes_uniform',
    'sodium_base642bin',
    'sodium_bin2base64',
    'trg_mask_update',
    'update_mask',
    'update_masks',
    'version'
]);

SELECT unnest(ARRAY[
    is(md5(prosrc), '02b31479ac60d88ea7851d2854c94bbe',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.valid_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_key'
    AND oidvectortypes(proargtypes) = 'pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamp with time zone, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_key'
    AND oidvectortypes(proargtypes) = 'pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamp with time zone, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_key'
    AND oidvectortypes(proargtypes) = 'pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamp with time zone, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_key'
    AND oidvectortypes(proargtypes) = 'pgsodium.key_type, text, bytea, bytea, uuid, bytea, timestamp with time zone, text';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'a34e96732392101c6e438288325151c0',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b034b801e006293fa2d4de77db4b1829',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, integer, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, integer, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'create_mask_view'
    AND oidvectortypes(proargtypes) = 'oid, integer, boolean';

SELECT unnest(ARRAY[
    is(md5(prosrc), '27fbda23b76401e3f3013342ead60241',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '565c3f6b7089c834b68540b8659937d9',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '93119aa464d9d356b792634f78c8eb99',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'e8a098b54847acfaca5da692af45bb63',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '43aadd3a9e9a3bed712f8e4c522a5138',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b0d161a2d27b62a738582204c6405c90',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'cf0c802e7d0719031ec0b0cae21c855e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '091354361e28ce3e06a90986fb4a5ff1',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '83c8690b4b89083750b09974ef8542eb',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '8055fdfe7a4fdd09f358b932d6890385',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_det_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '190fd05808f732c46260ae9d625d1688',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '28ce046099d429d397f9b87c64d0c2de',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'e876cddcf273954eced02ba954d4715a',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_decrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '61eb77dc541b65505402154ed9fb8d76',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'bf6098ffa90733e3c0929771089e0efe',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '6512ed7566d30f9e96ec8e6423e07fed',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_encrypt'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '80b50f97aa83b665b4cc9e58a7243db6',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '55202600f11e65666794a0522713798a',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_aead_ietf_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '51f19c953890536659e77edd6d48e6ac',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'e3555b53af815b902ab690858b7c59ab',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '42fe45fa1dc9ee6454b00e9066812724',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'd2b1a7c478e3a23998933a06033b7456',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '4d8c01b8311571e0bcaffa89cc95c730',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '861c1cf513df98a51cf423dcaaef73bb',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '87be98a80692ed952a5f9ce2e1e96332',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '1f9ca9e763e424762b9c679623b6e98c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'e9d4d91290446601f251e484ac882ce7',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b3dcc1305c045fdf12e539bb4150bbfc',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha256_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '41a984af503ec247e5aee27fc927f911',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '3659bd0b26a4321bf2e65a22a7f92067',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9c33f1bd0e34320cb9485067759581d7',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '19082e7e80449fa3bf4f8d5137f4ec53',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '24d597245855531b2b4d42f4a0890e15',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'd0a0a7255ae6bbe186684d9d8fd94add',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'e55ad9a0711f1c57d3f0275d275106c3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_hmacsha512_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'bb5de25c103707333034ca03c25af885',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '2326e9c78401cc0c5dec0d12bbe324cc',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '5b7e4bb4102a8161d83b075f688523e7',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ab469aac1e6c21b9f06fca1e439b653f',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_auth_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b39fc945ab0712cefc7c036cf0c101d4',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '8fcf35ee633e4befd5bb257bd4f2c579',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_box_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'a430924391e25e70d002641e013a4cb6',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '03e9192f0f0424138e07f0810d837c7d',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '5311d768585087f53330d79857de1bcb',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '20b889478bff61b2d29cf672c515dc16',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '155b2ed20459caf096e27be45a7a2d77',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seal_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '310490d8a5c128c8cb7d669a8012544e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_box_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_box_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b7b264c9d86060c05f37ab39dd9ffea5',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_cmp'
    AND oidvectortypes(proargtypes) = 'text, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_cmp'
    AND oidvectortypes(proargtypes) = 'text, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_cmp'
    AND oidvectortypes(proargtypes) = 'text, text';

SELECT unnest(ARRAY[
    is(md5(prosrc), '2fbabde39dcf93e5ff3abdcb15eff515',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '5a5efa2b6f1975f0d9be4567ae862d62',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '577e99ed40a9668f67e778c7049f06f2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '3f902416b07cceeb40b70ff87d6fcaa6',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_generichash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'bcbc6bcb399f683b5a9d49895b481a54',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha256'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha256'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha256'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9b722e50b03b4ce82cba278833f620d8',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha512'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha512'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_hash_sha512'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ab2dc05d028882a409ef6e9b9dc4af4d',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'bigint, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'bigint, bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'bigint, bigint, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '6c9c5dd5ae81124bf2fed4503b30b5b8',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'integer, bigint, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'integer, bigint, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_derive_from_key'
    AND oidvectortypes(proargtypes) = 'integer, bigint, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '392d0d6642f633a4706fc1651ae1458c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kdf_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'c904a08395162984f62affd3c25cb736',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_kx_session' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_client_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_client_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_client_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'bb1e551b92cd47e9110442195b1ffb73',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_kx_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '7a557ca636b54be357c7e6ab9a34f789',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9e92095db757fbd35e8ab9802ac0ceb4',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_kx_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '5c041123000b215e262761860a1eb69e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_kx_session' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_server_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_server_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_kx_server_session_keys'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '4a79b89a8f51713c89f0646bbe5cba85',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'd147e463fc05b8ea7b3c821889bbbab2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_saltgen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_saltgen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_saltgen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '841f7ed240ff8d175e9e31f4a47e9a24',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f81006e75ecef0edee12c7e95d4045d5',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_pwhash_str_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '88cbf924264a432cf3bfe1b3cd1372c2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '55879d5e82937acb264765f86c72d48f',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '23e406c911a735ae5552ce4ef1c43663',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '02c73ef185fc61c3bfc715dcee10880c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9289a1ea293547c485f2fde993d52101',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'd25f7a60931389bd0d2cc65bf307b597',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '67bf7825dc99cd84b427a618716c6294',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '7e6567b79efcdbe1d45fe4da14e23bc6',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretbox_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b755158a604630fec1f24384d098a150',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretstream_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretstream_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_secretstream_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '7d504833b157ad5ab63196391093b3ce',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ee8369a0df487859119161f97fc645be',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '6121ed2ed0f0792b27eea0850ef287ec',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'pgsodium_keymaker'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'pgsodium_keymaker')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'stable'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash'
    AND oidvectortypes(proargtypes) = 'bytea, uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f1bf578b8ab41a71c8b27e7273a9cd9e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_shorthash_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '40592a09473d35dc67c921d153e2e2a3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9cf53580e8b29f082d62d511b852cc6e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '485bd6025a0d5626fcc662e1cbf72d38',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_create'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_create'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_create'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '2206f3a06b092fc8e238fe20249527cd',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_final_verify'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'c1040c050835c2153f877d98c9e31784',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_init'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_init'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_init'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '4274d749001955c2a93e9f34f474a634',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_sign_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '5b040a5814896aa315935b938e762469',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '8e0bf2ec075f377a209737ffddda2c3f',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_open'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '459a5f8e20170fab983ba8749eb38d49',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_sign_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_seed_new_keypair'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f8794b8ec937fce1aab37cda1c39e860',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '3eb6d2f5e7ee95ed566dd6cdda54dac3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'internal'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_aggregate('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '3eb6d2f5e7ee95ed566dd6cdda54dac3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'internal'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_aggregate('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'a1ce52267e0fe2094d7dd4e73bfbad11',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg1'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg1'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg1'
    AND oidvectortypes(proargtypes) = 'bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'a7912e7e101ddce125d195d32bf25634',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg2'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg2'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_update_agg2'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '60c818250c3ce922aa97933e74fa20fd',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_verify_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_verify_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_sign_verify_detached'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'addc66b3cc31ba37c5864719ae38252c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_signcrypt_keypair' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_new_keypair'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'db08cbc0552880f60c5b7798b59a322b',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '2be5e49d785c6f5141b366dcbe91ddf3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_signcrypt_state_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_sign_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'd884a5c2b733f40f6a9ff360b1d234d5',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_after'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ffc1b7c5dd3c8d2540c50324093e2756',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.crypto_signcrypt_state_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_before'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b445fbe6062af1480220c4e924950139',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_public'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyholder', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_public'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_signcrypt_verify_public'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea, bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '2e33533ac0333efab4af30aeb3108429',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '6dcc978235d2dd998281a9c03448328e',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20'
    AND oidvectortypes(proargtypes) = 'bigint, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '7a713854d2449a937f2bff5f9f894585',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_keygen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ee2b4095aa6791a1a8cda00f9c8654ee',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_noncegen'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '1f008f536882e26237230d9b479ef468',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '68f3fc81eec25aebf4723678e8f1aa75',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'c157519b1d465f175b2dfa6facb264f2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '6957a516e5d08d79ed32db0e7ddb70c5',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'crypto_stream_xchacha20_xor_ic'
    AND oidvectortypes(proargtypes) = 'bytea, bytea, bigint, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b4f0ed3e736f56918a1367e8a4ecb153',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'decrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'decrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'decrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '12ad63eb60d8675ba3a4c62b51fbc6bc',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'derive_key'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'derive_key'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'derive_key'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f1e0010209d23ef71594c1b1d560dd72',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'disable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'disable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'disable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '06ed9c1478066fa5d1413c41d7457edd',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'enable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'enable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'enable_security_label_trigger'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'faacedb8c19aba1c5f9c7556d18c2286',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_column'
    AND oidvectortypes(proargtypes) = 'oid, record';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_column'
    AND oidvectortypes(proargtypes) = 'oid, record';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_column'
    AND oidvectortypes(proargtypes) = 'oid, record';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f0c7d467712320fda2f6dcafb2041fc7',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'encrypted_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '74de169dbf6e9283728f28292f6ab6c3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.valid_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_id'
    AND oidvectortypes(proargtypes) = 'uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_id'
    AND oidvectortypes(proargtypes) = 'uuid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_id'
    AND oidvectortypes(proargtypes) = 'uuid';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'dd4b7ca627ce0d929cb24610ef0e3854',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'pgsodium.valid_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_name'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_name'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_key_by_name'
    AND oidvectortypes(proargtypes) = 'text';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'c854af03ce8dcdf1e0ef1bed281602c9',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'setof pgsodium.valid_key' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_named_keys'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_named_keys'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'get_named_keys'
    AND oidvectortypes(proargtypes) = 'text';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'ac1bddc692d5ba3fcc189335c533cb36',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'boolean' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'has_mask'
    AND oidvectortypes(proargtypes) = 'regrole, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'has_mask'
    AND oidvectortypes(proargtypes) = 'regrole, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'has_mask'
    AND oidvectortypes(proargtypes) = 'regrole, text';

SELECT unnest(ARRAY[
    is(md5(prosrc), '52760b5073c9e61a42f29ea5c23bfe52',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'trigger' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'key_encrypt_secret_raw_key'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'key_encrypt_secret_raw_key'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'key_encrypt_secret_raw_key'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'dad5c5f648d4aec8e8142213de721039',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'setof record' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_columns'
    AND oidvectortypes(proargtypes) = 'oid';

SELECT unnest(ARRAY[
    is(md5(prosrc), '1b1d814a258347381f8989c6874dc01c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_role'
    AND oidvectortypes(proargtypes) = 'regrole, text, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_role'
    AND oidvectortypes(proargtypes) = 'regrole, text, text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'mask_role'
    AND oidvectortypes(proargtypes) = 'regrole, text, text';

SELECT unnest(ARRAY[
    is(md5(prosrc), '12ad63eb60d8675ba3a4c62b51fbc6bc',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'pgsodium_derive'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'pgsodium_derive'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'pgsodium_derive'
    AND oidvectortypes(proargtypes) = 'bigint, integer, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'b2c0dd700da6405825cc134b33ce8b1c',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'quote_assoc'
    AND oidvectortypes(proargtypes) = 'text, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'quote_assoc'
    AND oidvectortypes(proargtypes) = 'text, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'quote_assoc'
    AND oidvectortypes(proargtypes) = 'text, boolean';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'a957ffecfa7437ab87a9bc16349937d2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT unnest(ARRAY[
    is(md5(prosrc), '94530686103fae5b4e2d527d64ae3161',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf_deterministic'
    AND oidvectortypes(proargtypes) = 'integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf_deterministic'
    AND oidvectortypes(proargtypes) = 'integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf_deterministic'
    AND oidvectortypes(proargtypes) = 'integer, bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_buf_deterministic'
    AND oidvectortypes(proargtypes) = 'integer, bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '639d77e29e60e3736671c3e523fe30e3',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keymaker', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_new_seed'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '963110d850620792be51158a391bfad2',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'integer' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_random'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_random'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_random'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '9a2ab5b142ce979f25884a13dab1d924',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'integer' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_uniform'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'pgsodium_keyiduser', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_uniform'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'randombytes_uniform'
    AND oidvectortypes(proargtypes) = 'integer';

SELECT unnest(ARRAY[
    is(md5(prosrc), 'f38645aaf635b64acd980b74c8323d8d',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'bytea' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_base642bin'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_base642bin'
    AND oidvectortypes(proargtypes) = 'text';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_base642bin'
    AND oidvectortypes(proargtypes) = 'text';

SELECT unnest(ARRAY[
    is(md5(prosrc), '935b1cdc22710bc3b5fa417f52cd4f0a',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'c'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'immutable'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_bin2base64'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_bin2base64'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'sodium_bin2base64'
    AND oidvectortypes(proargtypes) = 'bytea';

SELECT unnest(ARRAY[
    is(md5(prosrc), '7e6641f8c9f661514f123598b1ca2448',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'event_trigger' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'trg_mask_update'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'trg_mask_update'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'trg_mask_update'
    AND oidvectortypes(proargtypes) = '';

SELECT unnest(ARRAY[
    is(md5(prosrc), '382a14e794ccad16439301eb9f8592b0',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    is_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_mask'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_mask'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_mask'
    AND oidvectortypes(proargtypes) = 'oid, boolean';

SELECT unnest(ARRAY[
    is(md5(prosrc), '4a6d5b9fa57e3dbe4f8b2067a6f67c78',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'plpgsql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'void' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_masks'
    AND oidvectortypes(proargtypes) = 'boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_masks'
    AND oidvectortypes(proargtypes) = 'boolean';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'update_masks'
    AND oidvectortypes(proargtypes) = 'boolean';

SELECT unnest(ARRAY[
    is(md5(prosrc), '4e1a2371fc8f546704bb9e0cfb488b72',
       format('Function pgsodium.%s(%s) body should match checksum',
              proname, pg_get_function_identity_arguments(oid))
    ),
    function_owner_is(
      'pgsodium'::name, proname,
      proargtypes::regtype[]::name[], 'postgres'::name,
      format('Function pgsodium.%s(%s) owner is %s',
             proname, pg_get_function_identity_arguments(oid), 'postgres')
    ),
    function_lang_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'sql'::name ),
    function_returns('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'text' ),
    volatility_is('pgsodium'::name, proname, proargtypes::regtype[]::name[], 'volatile'),
    isnt_definer('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    isnt_strict('pgsodium'::name, proname, proargtypes::regtype[]::name[]),
    is_normal_function('pgsodium'::name, proname, proargtypes::regtype[]::name[])
])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'version'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'postgres', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'version'
    AND oidvectortypes(proargtypes) = '';

SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], 'public', '{EXECUTE}'::text[])
  FROM pg_catalog.pg_proc
  WHERE pronamespace = 'pgsodium'::regnamespace
    AND proname = 'version'
    AND oidvectortypes(proargtypes) = '';




---- TYPES

SELECT types_are('pgsodium', ARRAY[
    '_key_id_context',
    'crypto_box_keypair',
    'crypto_kx_keypair',
    'crypto_kx_session',
    'crypto_sign_keypair',
    'crypto_signcrypt_keypair',
    'crypto_signcrypt_state_key',
    'key_status',
    'key_type'
]);

SELECT type_owner_is('pgsodium'::name, '_key_id_context'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_box_keypair'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_kx_keypair'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_kx_session'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_sign_keypair'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_signcrypt_keypair'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'crypto_signcrypt_state_key'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'key_status'::name, 'postgres'::name);
SELECT type_owner_is('pgsodium'::name, 'key_type'::name, 'postgres'::name);



---- ENUMS

SELECT enums_are('pgsodium', ARRAY[
    'key_status',
    'key_type'
]);

SELECT enum_has_labels('pgsodium','key_status', ARRAY['default','valid','invalid','expired']);
SELECT enum_has_labels('pgsodium','key_type', ARRAY['aead-ietf','aead-det','hmacsha512','hmacsha256','auth','shorthash','generichash','kdf','secretbox','secretstream','stream_xchacha20']);
