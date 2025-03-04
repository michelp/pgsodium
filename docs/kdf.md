``` postgres-console
NOTICE:  extension "pgsodium" already exists, skipping
```
# Server Key Management

The core feature of pgsodium its its ability to manage encryption keys
for you, you so that you never reference a raw encryption key, but
instead you reference keys *by ID*.  A key id is a UUID that uniquely
identifies the key used.  An example of using Server Key Management
can be found in the section on [Column
Encryption](tce.md) and is most of the API
examples that can take key UUIDs are arguments.

## Create a new Key

pgsodium can manage two types of keys, *derived* keys, and *external*
keys.  Derived keys use libsodium to

Server managed keys are created with the `pgsodium.create_key()`
function.  This function takes a few optional parameters:

- `key_type`: The type of key to create, the default is `aead-det`.
  Can be one of:

  - `aead-det`
  - `aead-ietf`
  - `hmacsha512`
  - `hmacsha256`
  - `auth`
  - `secretbox`
  - `secretstream`
  - `shorthash`
  - `generichash`
  - `kdf`

- `name`: An optional *unique* name for the key.  The default is NULL
  which makes an "anonymous" key.

- `derived_key`: An optional raw external key, for example an hmac key
  from an external service.  pgsodium will store this key encrypted
  with TCE.

- `derived_key_nonce`: An optional nonce for the raw key, if none is
  provided a new random `aead-det` nonce will be generated using
  `pgsodium.crypto_aead_det_noncegen()`.

- `parent_key`: If `raw_key` is not null, then this key id is used to
  encrypt the raw key.  The default is to generate a new `aead-det`
  key.

- `derived_context`

- `expires`

- `associated_data`

`pgsodium.create_key()` returns a new row in the `pgsodium.valid_key`
view.  For most purposes, you usually just need the new key's ID to
start using it.  For example, here's a new external shahmac256 key
being created and used to verify a payload:
``` postgres-console
select pgsodium.crypto_auth_hmacsha256_keygen() key \gset
select * from pgsodium.create_key('hmacsha256', raw_key:=:'external_key');
ERROR:  syntax error at or near ":"
LINE 1: ...* from pgsodium.create_key('hmacsha256', raw_key:=:'external...
                                                             ^
select id, key_type, parent_key, length(decrypted_raw_key) from pgsodium.decrypted_key where key_type = 'hmacsha256';
┌────┬──────────┬────────────┬────────┐
│ id │ key_type │ parent_key │ length │
├────┼──────────┼────────────┼────────┤
└────┴──────────┴────────────┴────────┘
(0 rows)

```