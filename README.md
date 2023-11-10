[![Tests](https://github.com/michelp/pgsodium/actions/workflows/test.yml/badge.svg)](https://github.com/michelp/pgsodium/actions/workflows/test.yml)

# pgsodium

pgsodium is an encryption library extension for
[PostgreSQL](https://www.postgresql.org/) using the
[libsodium](https://download.libsodium.org/doc/) library for high
level cryptographic algorithms.

pgsodium can be used a straight interface to libsodium, but it can
also use a powerful feature called [Server Key
Management](#server-key-management) where pgsodium loads an external
secret key into memory that is never accessible to SQL.  This
inaccessible root key can then be used to derive sub-keys and keypairs
*by key id*.  This id (type `bigint`) can then be stored *instead of
the derived key*.

Another advanced feature of pgsodium is [Transparent Column
Encryption](#transparent-column-encryption) which can automatically
encrypt and decrypt one or more columns of data in a table.

# Table of Contents

   * [pgsodium](#pgsodium)
      * [Installation](#installation)
   * [Usage](#usage)
   * [Server Key Management](#server-key-management)
   * [Server Key Derivation](#server-key-derivation)
   * [Key Management API](#key-management-table)
   * [Security Roles](#security-roles)
   * [Transparent Column Encryption](#transparent-column-encryption)
   * [Simple public key encryption with crypto_box()](#simple-public-key-encryption-with-crypto_box)
   * [Avoid secret logging](#avoid-secret-logging)
   * [API Reference](#api-reference)
      * [Generating Random Data](#generating-random-data)
      * [Secret key cryptography](#secret-key-cryptography)
         * [Authenticated encryption](#authenticated-encryption)
         * [Authentication](#authentication)
      * [Public key cryptography](#public-key-cryptography)
         * [Authenticated encryption](#authenticated-encryption-1)
         * [Public key signatures](#public-key-signatures)
         * [Sealed boxes](#sealed-boxes)
      * [Hashing](#hashing)
      * [Password hashing](#password-hashing)
      * [Key Derivation](#key-derivation)
      * [Key Exchange](#key-exchange)
      * [HMAC512](#hmac512)
      * [Advanced Stream API](#advanced-stream-api)
      * [XChaCha20-SIV](#xchacha20-siv)
      * [Signcryption](#signcryption)

## Installation

pgsodium requires libsodium >= 1.0.18.  In addition to the libsodium
library and it's development headers, you may also need the PostgreSQL
header files typically in the '-dev' packages to build the extension.

After installing the dependencies, clone the repo and run `sudo make
install`.  You can also install pgsodium through the pgxn extension
network with `pgxn install pgsodium`.

pgTAP tests can be run with `sudo -u postgres pg_prove test.sql` or
they can be run in a self-contained Docker image.  Run `./test.sh` if
you have docker installed to run all tests.

As of version 3.0.0 pgsodium requires PostgreSQL 14+.  Use pgsodium
2.0.* for earlier versions of Postgres.  Once you have the extension
correctly compiled you can install it into your database using the
SQL:

```
CREATE EXTENSION pgsodium;
```

Note that pgsodium is very careful about the risk of `search_path`
hacking and must go into a database schema named `pgsodium`.  The
above command will automatically create that schema.  You are
encouraged to always reference pgsodium functions by their fully
qualified names, or by making sure that the `pgsodium` schema is first
in your `search_path`.

# Usage

Without using the optional [Server Managed
Keys](#server-key-management) feature pgsodium is a simple and
straightforward interface to the libsodium API.

pgsodium arguments and return values for content and keys are of type
`bytea`.  If you wish to use `text` or `varchar` values for general
content, you must make sure they are encoded correctly.  The
[`encode() and decode()` and
`convert_to()/convert_from()`](https://www.postgresql.org/docs/current/functions-binarystring.html)
binary string functions can convert from `text` to `bytea`.  Simple
ascii `text` strings without escape or unicode characters will be cast
by the database implicitly, and this is how it is done in the tests to
save time, but you should really be explicitly converting your `text`
content if you wish to use pgsodium without conversion errors.

Most of the libsodium API is available as SQL functions.  Keys that
are generated in pairs are returned as a record type, for example:

```
postgres=# SELECT * FROM crypto_box_new_keypair();
                               public                               |                               secret
--------------------------------------------------------------------+--------------------------------------------------------------------
 \xa55f5d40b814ae4a5c7e170cd6dc0493305e3872290741d3be24a1b2f508ab31 | \x4a0d2036e4829b2da172fea575a568a74a9740e86a7fc4195fe34c6dcac99976
(1 row)
```

pgsodium is careful to use memory cleanup callbacks to zero out all
allocated memory used when freed.  In general it is a bad idea to
store secrets in the database itself, although this can be done
carefully it has a higher risk.  To help with this problem, pgsodium
has an optional Server Key Management function that can load a hidden
server key at boot that other keys are *derived* from.

# Server Key Management

If you add pgsodium to your
[`shared_preload_libraries`](https://www.postgresql.org/docs/current/runtime-config-client.html#RUNTIME-CONFIG-CLIENT-PRELOAD)
configuration and place a special script in your postgres shared
extension directory, the server can preload a libsodium key on server
start. **This root secret key cannot be accessed from SQL**.  The only
way to use the server secret key is to derive other keys from it using
`derive_key()` or use the key_id variants of the API that take key ids
and contexts instead of raw `bytea` keys.

Server managed keys are completely optional, pgsodium can still be
used without putting it in `shared_preload_libraries`, but you will
need to provide your own key management.  Skip ahead to the API usage
section if you choose not to use server managed keys.

See the file
[`getkey_scripts/pgsodium_getkey_urandom.sh`](getkey_scripts/pgsodium_getkey_urandom.sh)
for an example script that returns a libsodium key using the linux
`/dev/urandom` CSPRNG.

pgsodium also comes with example scripts for:

  - [Amazon Web Service's Key Management
    Service](getkey_scripts/pgsodium_getkey_aws.sh).

  - [Google Cloud's Cloud Key
    Management](getkey_scripts/pgsodium_getkey_gcp.sh).

  - [Doppler SecretOps Platform](getkey_scripts/pgsodium_getkey_doppler.sh).

  - [Zymbit Zymkey 4i Hardware Security
    Module](getkey_scripts/pgsodium_getkey_zmk.sh).

Next place `pgsodium` in your `shared_preload_libraries`.  For docker
containers, you can append this after the run:

    docker run -d ... -c 'shared_preload_libraries=pgsodium'

When the server starts, it will load the secret key into memory, but
this key is *never* accessible to SQL.  It's possible that a
sufficiently clever malicious superuser can access the key by invoking
external programs, causing core dumps, looking in swap space, or other
attack paths beyond the scope of pgsodium.  Databases that work with
encryption and keys should be extra cautious and use as many process
hardening mitigations as possible.

It is up to you to edit the get key script to get or generate the key
however you want.  pgsodium can be used to generate a new random key
with `select encode(randombytes_buf(32), 'hex')`.  Other common
patterns including prompting for the key on boot, fetching it from an
ssh server or managed cloud secret system, or using a command line
tool to get it from a hardware security module.

You can specify the location of the get key script with a database
configuration variable in either `postgresql.conf` or using `ALTER
SYSTEM`:

    pgsodium.getkey_script = 'path_to_script'

# Server Key Derivation

New keys are derived from the primary server secret key by id and an
optional context using the [libsodium Key Derivation
Functions](https://doc.libsodium.org/key_derivation).  Key id are just
`bigint` integers.  If you know the key id, key length (default 32
bytes) and the context (default 'pgsodium'), you can deterministicly
generate a derived key.

Derived keys can be used to encrypt data or as a seed for
deterministicly generating keypairs using `crypto_sign_seed_keypair()`
or `crypto_box_seed_keypair()`.  It is wise not to store these secrets
but only store or infer the key id, length and context.  If an
attacker steals your database image, they cannot generate the key even
if they know the key id, length and context because they will not have
the server secret key.

The key id, key length and context can be secret or not, if you store
them then possibly logged in database users can generate the key if
they have permission to call the `derive_key()` function.
Keeping the key id and/or length context secret to a client avoid this
possibility and make sure to set your [database security
model](https://www.postgresql.org/docs/current/sql-grant.html) correctly so
that only the minimum permission possible is given to users that
interact with the encryption API.

Key rotation is up to you, whatever strategy you want to go from one
key to the next.  A simple strategy is incrementing the key id and
re-encrypting from N to N+1.  Newer keys will have increasing ids, you
can always tell the order in which keys are superceded.

A derivation context is an 8 byte `bytea`. The same key id in
different contexts generate different keys.  The default context is
the ascii encoded bytes `pgsodium`.  You are free to use any 8 byte
context to scope your keys, but remember it must be a valid 8 byte
`bytea` which automatically cast correctly for simple ascii string.
For encoding other characters, see the [`encode() and decode()` and
`convert_to()/convert_from()`](https://www.postgresql.org/docs/current/functions-binarystring.html)
binary string functions.  The derivable keyspace is huge given one
`bigint` keyspace per context and 2^64 contexts.

To derive a key:

    # select derive_key(1);
                              derive_key
    --------------------------------------------------------------------
     \x84fa0487750d27386ad6235fc0c4bf3a9aa2c3ccb0e32b405b66e69d5021247b

    # select derive_key(1, 64);
                                                              derive_key
    ------------------------------------------------------------------------------------------------------------------------------------
     \xc58cbe0522ac4875707722251e53c0f0cfd8e8b76b133f399e2c64c9999f01cb1216d2ccfe9448ed8c225c8ba5db9b093ff5c1beb2d1fd612a38f40e362073fb

    # select derive_key(1, 32, '__auth__');
                              derive_key
    --------------------------------------------------------------------
     \xa9aadb2331324f399fb58576c69f51727901c651c970f3ef6cff47066ea92e95

The default keysize is `32` and the default context is `'pgsodium'`.

Derived keys can be used either directly in `crypto_secretbox_*`
functions for "symmetric" encryption or as seeds for generating other
keypairs using for example `crypto_box_seed_new_keypair()` and
`crypto_sign_seed_new_keypair()`.

    # select * from crypto_box_seed_new_keypair(derive_key(1));
                                   public                               |                               secret
    --------------------------------------------------------------------+--------------------------------------------------------------------
     \x01d0e0ec4b1fa9cc8dede88e0b43083f7e9cd33be4f91f0b25aa54d70f562278 | \x066ec431741a9d39f38c909de4a143ed39b09834ca37b6dd2ba3d015206f14ca

# Key Management API

pgsodium provides an API and internal table and view for simple key id
and context managment.  This table provides a number of useful columns
including experation capability.  Keys generated with this API must be
used for the [Transparent Column
Encryption](#transparent-column-encryption) features.

Managed Keys have UUIDs for indentifiers, these UUIDs are used to
lookup keys in the table.  Note that the key management is based on
the same [Server Key Management](#server-key-management) that uses the
internal hidden root key, so both the Key Management API and
Transparent Column Encryption require it.

To create a new key, call the `pgsodium.create_key()` function:

```
# select * from pgsodium.create_key();
-[ RECORD 1 ]-------------------------------------
id          | 74d97ba2-f9e3-4a64-a032-8427cd6bd686
status      | valid
created     | 2022-08-04 05:06:53.878502
expires     |
key_type    | aead-det
key_id      | 4
key_context | \x7067736f6469756d
comment     | This is an optional comment
user_data   |

```

`pgsodium.create_key()` takes the following arguments, all of them are
optional:

  - `key_type pgsodium.key_type = 'aead-det'`: The type of key to
     create.If you do not specify a `raw_key` argument, a new derived
     key_id of the correct type will be automatically generated in
     `key_context` argument context.  Possible values are:
     - `aead-det`
     - `aead-ietf`
     - `hmacsha512`
     - `hmacsha256`
     - `auth`
     - `shorthash`
     - `generichash`
     - `kdf`
     - `generichash`
     - `kdf`
     - `secretbox`
     - `secretstream`
  - `name text = null`: The optional unique name of the key.
  - `raw_key bytea = null`: A raw key to store encrypted, if not
    specified, the raw key is derived from `key_id` and `key_context`.
  - `raw_key_nonce bytea = null`: The nonce used to encrypt the raw
    key with, if not specified a new random nonce will be generated.
  -  `key_context bytea = 'pgsodium'`: The libsodium context to use
     for derivation if `key_id` is not null.
  - `parent_key uuid = null`: The parent key use to encrypt the raw
    key.  If not specified, a new unnamed key is created.
  - `expires timestamptz = null`: The expiration time checked by the
    `pgsodium.valid_key` view.
  - `associated_data text = ''`: Extra user data you can associate
    with the encrypted raw key.  This data is appended to the key
    UUID, and mixed into the encryption signature and can be
    authenticated with it.

Keys of the type `aead-det` can be used for [Transparent Column
Encryption](#transparent-column-encryption).  The view
`pgsodium.valid_keys` filters the key table for only keys that are
valid and not expired.

# Security Roles

The pgsodium API has two nested layers of security roles:

  - `pgsodium_keyiduser` Is the less privileged role that can only
    access keys by their UUID.  This is the role you would typically
    give to a user facing application.

  - `pgsodium_keymaker` is the more privileged role and can work with
    raw `bytea` And managed server keys.  You would not typically give
    this role to a user facing application.

Note that public key apis like `crypto_box` and `crypto_sign` do not
have "key id" variants, because they work with a combination of four
keys, two keypairs for each of two parties.

As the point of public key encryption is for each party to keep their
secrets and for that secret to not be centrally derivable.  You can
certainly call something like `SELECT * FROM
crypto_box_seed_new_keypair(derive_key(1))` and make deterministic
keypairs, but then if an attacker steals your root key they can derive
all keypair secrets, so this approach is not recommended.

# Transparent Column Encryption

pgsodium provides a useful pattern where a trigger is used to encrypt
a column of data in a table which is then decrypted using a view.
This is called *Transparent Column Encryption* and can be enabled with
pgsodium using the [SECURITY LABEL ...]() PostgreSQL command.

If an attacker acquires a dump of the table or database, they will not
be able to derive the keys used to encrypt the data since they will
not have the root server managed key, which is never revealed to SQL
See the [example file for more details](./example/tce.sql).

In order to use TCE you must use keys created from the [Key Management
Table](#key-management-table) API.  This API returns key ids that are
UUIDs for use with the internal encryption functions used by the TCE
functionality.  Creating a key to use is the first step:

```
# select * from pgsodium.create_key();
-[ RECORD 1 ]-------------------------------------
id                | dfc44293-fa78-4a1a-9ef9-7e600e63e101
status            | valid
created           | 2022-08-03 18:50:53.355099
expires           |
key_type          | aead-det
key_id            | 5
key_context       | \x7067736f6469756d
comment           |
associated_data   |
```

This key is now stored in the `pgsodium.key` table, and can be
accessed via the `pgsodium.valid_key` view:

```
# select EXISTS (select 1 from pgsodium.valid_key where id = 'dfc44293-fa78-4a1a-9ef9-7e600e63e101');
-[ RECORD 1 ]
exists | t
```

Now this key id can be used for simple TCE as shown in the next section.

## One Key Id for the Entire Column

For the simplest case, a column can be encrypted with one key id which
must be of the type `aead-det` (as created above):

```sql
CREATE TABLE private.users (
	id bigserial primary key,
	secret text);

SECURITY LABEL FOR pgsodium	ON COLUMN private.users.secret
  IS 'ENCRYPT WITH KEY ID dfc44293-fa78-4a1a-9ef9-7e600e63e101';
```

The advantage of this approach is it is very simple, the user creates
one key and labels a column with it.  The cryptographic algorithm for
this approach uses a *nonceless* encryption algorithm called
`crypto_aead_det_xchacha20()`.  If you wish to use a nonce value, see
below.

## One Key ID per Row

Using one key for an entire column means that whoever can decrypt one
row can decrypt them all from a database dump.  Also changing
(rotating) the key means rewriting the whole table.

A more fine grained approach is to store one key id per row:

```sql
CREATE TABLE private.users (
	id bigserial primary key,
	secret text,
	key_id uuid not null,
  nonce bytea
);

SECURITY LABEL FOR pgsodium
	ON COLUMN private.users.secret
  IS 'ENCRYPT WITH KEY COLUMN key_id;
```

This approach ensures that “cracking” the key for one row does not
help decrypt any others.  It also acts as a natural partition that can
work in conjunction with RLS to share distinct keys between owners.

## One Key ID per Row with Nonce Support

The default cryptographic algorithm for the above approach uses a
*nonceless* encryption algorithm called `crypto_aead_det_xchacha20()`.
This scheme has the advantage that it does not require nonce values,
the disadvantage is that duplicate plaintexts will produce duplicate
ciphertexts, but this information can not be used to attack the key it
can only reveal the duplication.

However duplication is still information, and if you want more
security, slightly better performance, or you require duplicate
plaintexts to have *different* ciphertexts, a unique *nonce* can be
provided that mixes in some additional non-secret data that
deduplicates ciphertexts for duplicate plaintext:

```sql
CREATE TABLE private.users (
	id bigserial primary key,
	secret text,
	key_id uuid not null,
    nonce bytea
);

SECURITY LABEL FOR pgsodium
	ON COLUMN private.users.secret
  IS 'ENCRYPT WITH KEY COLUMN key_id NONCE nonce';
```
## One Key ID per Row with Nonce Support and Associated Data

The `aead-det` algorithm can mix user provided data into the
authentication signature for the encrypted secret.  This
"authenticates" the plaintext and ensures that it has not been altered
(or the decryption will fail).  This is useful for associated useful
metadata with your secrets:

```sql
CREATE TABLE private.users (
	id bigserial primary key,
	secret text,
	key_id uuid not null,
    nonce bytea,
    associated_data text
);

SECURITY LABEL FOR pgsodium
	ON COLUMN private.users.secret
  IS 'ENCRYPT WITH KEY COLUMN key_id NONCE nonce ASSOCIATED (id, associated_data)';
```

You can specify multiple columns as shown above with both the id and
associated data column.  Columns used for associated data must be
*deterministicly* castable to `text`.

## TCE and `ON CONFLICT UPDATE` Clauses "UPSERT" Pattern

UPSERT is not a command in PostgreSQL, it is one pattern among many
possible when using the `INSERT ... ON CONFLICT DO ...` clause in
Postgres to either insert a value, or do some other action, which is
commonly to update the alreadt extant row that the command was
attempting to INSERT.  This pattern usually looks like:

```sql
INSERT INTO my_table (my_columns...) VALUES (new_values...)
  ON CONFLICT (some_unique_key_like_id) DO UPDATE
  SET my_data = EXCLUDED.my_data;
```

The statement tries to insert a row, and if there is a unique
constraint violation, it will instead update the row with the value of
the row that was about to be inserted.

Unfortunately, the value of the row that was about to be inserted is
already encrypted, so this pattern does not work, instead to do an
"UPSERT" you must combine the unencrypted data from the view with the
encryted data in the table, so that the unencrypted value is
"reencrypted" correctly and not "double encrypted".

The function below shows how this query can be formatted as a stored
procedure, if you are using PostgREST, this is the "RPC" function to
use to do the intended upsert behavior:

```sql
CREATE OR REPLACE FUNCTION upsert_test(p_id bigint, p_name text DEFAULT NULL, p_secret text DEFAULT NULL)
    RETURNS test LANGUAGE sql AS
    $$
    INSERT INTO test (id, name, secret) VALUES (p_id, p_name, p_secret)
    ON CONFLICT (id) DO UPDATE
        SET name   = coalesce(p_name, (SELECT name FROM test WHERE id = p_id)),
            secret = coalesce(p_secret, (SELECT decrypted_secret FROM decrypted_test WHERE id = p_id))
    RETURNING *
    $$;
```

If you do not need the stored procedure you can modify the inner query
to suite your specific needs as a literal SQL query.

## Postgres 15 and "Security Invoker" Views

Postgres 15 added a new propery to views called `security_invoker`
which changes the behavior of views that access an underlying table
with row security labels.  Before pg15, all views ran as the owner of
the view itself, making interaction with RLS clumsy, starting with
pg15, views that are marked as `security_invoker` will "run" with the
privileges of the invoking user, not the owner of the view, this makes
working with RLS policies simpler.

Any TCE security label can be appended with the string `SECURITY
INVOKER' which will cause the automatically generated view to be
marked `security_invoker=true`.  Note that you are still responsible
for understanding the grants/revokes to your view and table, which can
vary depending on the specific needs of your application's security
model.

## Inspecting Security Labels

The system catalog `pg_seclabel` can be hard to decipher, requiring
joins to figure out which labels apply to which columns.  The
`pgsodium.seclabel` view simplifies this task by resolving the table
and column names for you:

```
postgres=> select * from pgsodium.seclabel ;
-[ RECORD 1 ]---------------------------------------------------------------------------------------------------------
nspname | tce-example
relname | test2
attname | secret2
label   | ENCRYPT WITH KEY COLUMN secret2_key_id ASSOCIATED (id, associated2) NONCE nonce2
-[ RECORD 2 ]---------------------------------------------------------------------------------------------------------
nspname | tce-example
relname | test2
attname | secret
label   | ENCRYPT WITH KEY ID f8db208c-8201-466a-98cd-b0d91f5326ca ASSOCIATED (associated) NONCE nonce
-[ RECORD 3 ]---------------------------------------------------------------------------------------------------------
nspname | tce-example
relname | test
attname | secret
label   | ENCRYPT WITH KEY ID 2a5500f3-9378-4134-89db-5fd870a5ce7a
-[ RECORD 4 ]---------------------------------------------------------------------------------------------------------
nspname | pgsodium
relname | key
attname | raw_key
label   | ENCRYPT WITH KEY COLUMN parent_key ASSOCIATED (id, associated_data) NONCE raw_key_nonce
-[ RECORD 5 ]---------------------------------------------------------------------------------------------------------
nspname | tce-example
relname | bob-testt
attname | secret2-test
label   | ENCRYPT WITH KEY COLUMN secret2_key_id-test ASSOCIATED (associated2-test) NONCE nonce2-test SECURITY INVOKER
```

## Disabling View and Trigger generation

If you wish to disable the `EVENT TRIGGER` that fires and generates
the trigger and view, you can turn if off with a configuration
setting:

```sql
SET pgsodium.enable_event_trigger = 'off';
```

This parameter can be set in the `postgresql.conf` file, or passed to
the server on startup with `-C`.  Disabling trigger generation can be
useful for doing migrations when you don't want trigger generation to
get in the way of copying DDL from one system to another.  See the
postgres docs for [Setting
Parameters](https://www.postgresql.org/docs/current/config-setting.html).

# Simple public key encryption with `crypto_box()`

Here's an example usage from the test.sql that uses command-line
[`psql`](https://www.postgresql.org/docs/current/app-psql.html) client
commands (which begin with a backslash) to create keypairs and encrypt
a message from Alice to Bob.

    -- Generate public and secret keypairs for bob and alice
    -- \gset [prefix] is a psql command that will create local
    -- script variables

    SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
    SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

    -- Create a boxnonce

    SELECT crypto_box_noncegen() boxnonce \gset

    -- Alice encrypts the box for bob using her secret key, the nonce and his public key

    SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

    -- Bob decrypts the box using his secret key, the nonce, and Alice's public key

    SELECT crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret');

Note in the above example, no secrets are *stored* in the db, but they
are *interpolated* into the sql by the psql client that is sent to the
server, so it's possible they can show up in the database logs.  You
can avoid this by using derived keys.

# Avoid secret logging

If you choose to work with your own keys and not restrict yourself to
the `pgsodium_keyiduser` role, a useful approach is to keep keys in an
external storage and disables logging while injecting the keys into
local variables with [`SET
LOCAL`](https://www.postgresql.org/docs/current/sql-set.html). If the
images of database are hacked or stolen, the keys will not be
available to the attacker.

To disable logging of the key injections, `SET LOCAL` is also used to
disable
[`log_statements`](https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT)
and then re-enable normal logging afterwards. as shown below. Setting
`log_statement` requires superuser privileges:

    -- SET LOCAL must be done in a transaction block
    BEGIN;

    -- Generate a boxnonce, and public and secret keypairs for bob and alice
    -- This creates secrets that are sent back to the client but not stored
    -- or logged.  Make sure you're using an encrypted database connection!

    SELECT crypto_box_noncegen() boxnonce \gset
    SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
    SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

    -- Turn off logging and inject secrets
    -- into session with set local, then resume logging.

    SET LOCAL log_statement = 'none';
    SET LOCAL app.bob_secret = :'bob_secret';
    SET LOCAL app.alice_secret = :'alice_secret';
    RESET log_statement;

    -- Now call the `current_setting()` function to get the secrets, these are not
    -- stored in the db but only in session memory, when the session is closed they are no longer
    -- accessible.

    -- Alice encrypts the box for bob using her secret key and his public key

    SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public',
                      current_setting('app.alice_secret')::bytea) box \gset

    -- Bob decrypts the box using his secret key and Alice's public key.

    SELECT crypto_box_open(:'box', :'boxnonce', :'alice_public',
                              current_setting('app.bob_secret')::bytea);

    COMMIT;

For additional paranoia you can use a function to check that the
connection being used is secure or a unix domain socket.

    CREATE FUNCTION is_ssl_or_domain_socket() RETURNS bool
    LANGUAGE plpgsql AS $$
    DECLARE
        addr text;
	    ssl text;
    BEGIN
        SELECT inet_client_addr() INTO addr;
        SELECT current_setting('ssl', true) INTO ssl;
        IF NOT FOUND OR ((ssl IS NULL OR ssl != 'on')
            AND (addr IS NOT NULL OR length(addr) != 0))
        THEN
            RETURN false;
        END IF;
        RETURN true;
    END;
    $$;

This doesn't guarantee the secret won't leak out in some way of
course, but it can useful if you never store secrets and send them
only through secure channels back to the client, for example using the
`psql` client `\gset` command shown above, or by only storing a
derived key id and context.

# API Reference

The reference below is adapted from and uses some of the same language
found at the [libsodium C API
Documentation](https://doc.libsodium.org/).  Refer to those documents
for details on algorithms and other libsodium specific details.

The libsodium documentation is Copyright (c) 2014-2018, Frank Denis
<github@pureftpd.org> and released under [The ISC
License](https://github.com/jedisct1/libsodium-doc/blob/master/LICENSE).

## Generating Random Data

Functions:
```
    randombytes_random() -> integer

    randombytes_uniform(upper_bound integer) -> integer

    randombytes_buf(size integer) -> bytea

```

The library provides a set of functions to generate unpredictable
data, suitable for creating secret keys.

    # select randombytes_random();
     randombytes_random
    --------------------
             1229887405
    (1 row)

The `randombytes_random()` function returns an unpredictable value
between 0 and 0xffffffff (included).

    # select randombytes_uniform(42);
     randombytes_uniform
    ---------------------
                      23
    (1 row)

The `randombytes_uniform()` function returns an unpredictable value
between `0` and `upper_bound` (excluded). Unlike `randombytes_random() %
upper_bound`, it guarantees a uniform distribution of the possible
output values even when `upper_bound` is not a power of 2. Note that an
`upper_bound < 2` leaves only a single element to be chosen, namely 0.

    # select randombytes_buf(42);
                                        randombytes_buf
    ----------------------------------------------------------------------------------------
     \x27cec8d2c3de16317074b57acba2109e43b5623e1fb7cae12e8806daa21a72f058430f22ec993986fcb2
    (1 row)

The `randombytes_buf()` function returns a `bytea` with an
unpredictable sequence of bytes.

    # select randombytes_new_seed() bufseed \gset
    # select randombytes_buf_deterministic(42, :'bufseed');
                                 randombytes_buf_deterministic
    ----------------------------------------------------------------------------------------
     \xa183e8d4acd68119ab2cacd9e46317ec3a00a6a8820b00339072f7c24554d496086209d7911c3744b110
    (1 row)

The `randombytes_buf_deterministic()` returns a `size` bytea
containing bytes indistinguishable from random bytes without knowing
the seed.  For a given seed, this function will always output the same
sequence. size can be up to 2^38 (256 GB).

[C API
Documentation](https://doc.libsodium.org/generating_random_data)

## Secret key cryptography


[C API
Documentation](https://doc.libsodium.org/secret-key_cryptography)

### Authenticated encryption

Functions:
```
    crypto_secretbox_keygen() -> bytea

    crypto_secretbox_noncegen() -> bytea

    crypto_secretbox(message bytea, nonce bytea, key bytea) -> bytea

    crypto_secretbox_open(ciphertext bytea, nonce bytea, key bytea) -> bytea
```

`crypto_secretbox_keygen()` generates a random secret key which can be
used to encrypt and decrypt messages.

`crypto_secretbox_noncegen()` generates a random nonce which will be
used when encrypting messages.  For security, each nonce must be used
only once, though it is not a secret.  The purpose of the nonce is to
add randomness to the message so that the same message encrypted
multiple times with the same key will produce different ciphertexts.

`crypto_secretbox()` encrypts a message using a previously generated
nonce and secret key or key id.  The encrypted message can be
decrypted using `crypto_secretbox_open()` Note that in order to
decrypt the message, the original nonce will be needed.

`crypto_secretbox_open()` decrypts a message encrypted by
`crypto_secretbox()`.

[C API
Documentation](https://doc.libsodium.org/secret-key_cryptography/secretbox)

### Authentication

Functions:
```
    crypto_auth_keygen() -> bytea

    crypto_auth(message bytea, key bytea) -> bytea

    crypto_auth_verify(mac bytea, message bytea, key bytea) -> boolean
```

`crypto_auth_keygen()` generates a message-signing key for use by
`crypto_auth()`.

`crypto_auth()` generates an authentication tag (mac) for a
combination of message and secret key.  This does not encrypt the
message; it simply provides a means to prove that the message has not
been tampered with.  To verify a message tagged in this way, use
`crypto_auth_verify()`.  This function is deterministic: for a given
message and key, the generated mac will always be the same.

Note that this requires access to the secret
key, which is not something that should normally be shared.  If
many users need to verify message it is usually better to use
[Public Key Signatures](#user-content-public-key-signatures) rather
than sharing secret keys.

`crypto_auth_verify()` verifies that the given mac (authentication
tag) matches the supplied message and key.  This tells us that the
original message has not been tampered with.

[C API
Documentation](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)
## Public key cryptography

[C API
Documentation](https://doc.libsodium.org/public-key_cryptography)

### Authenticated encryption

Functions:
```
    crypto_box_new_keypair() -> crypto_box_keypair

    crypto_box_noncegen() -> bytea

    crypto_box(message bytea, nonce bytea,
               public bytea, secret bytea) -> bytea

    crypto_box_open(ciphertext bytea, nonce bytea,
                    public bytea, secret bytea) -> bytea
```

`crypto_box_new_keypair()` returns a new, randomly generated, pair of
keys for public key encryption.  The public key can be shared with
anyone.  The secret key must never be shared.

`crypto_box_noncegen()` generates a random nonce which will be used
when encrypting messages.  For security, each nonce must be used only
once, though it is not a secret.  The purpose of the nonce is to add
randomness to the message so that the same message encrypted multiple
times with the same key will produce different ciphertexts.

`crypto_box()` encrypts a message using a nonce, the intended
recipient's public key and the sender's secret key.  The resulting
ciphertext can only be decrypted by the intended recipient using their
secret key.  The nonce must be sent along with the ciphertext.

`crypto_box_open()` decrypts a ciphertext encrypted using
`crypto_box()`.  It takes the ciphertext, nonce, the sender's public
key and the recipient's secret key as parameters, and returns the
original message.  Note that the recipient should ensure that the
public key belongs to the sender.

[C API
Documentation](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)

### Public key signatures


Functions:
```
    crypto_sign_new_keypair() -> crypto_sign_keypair

  combined mode functions:

    crypto_sign(message bytea, key bytea) -> bytea

    crypto_sign_open(signed_message bytea, key bytea) -> bytea

  detached mode functions:

    crypto_sign_detached(message bytea, key bytea) -> bytea

    crypto_sign_verify_detached(sig bytea, message bytea, key bytea) -> boolean

  multi-part message functions:

    crypto_sign_init() -> bytea

    crypto_sign_update(state bytea, message bytea) -> bytea

    crypto_sign_final_create(state bytea, key bytea) -> bytea

    crypto_sign_final_verify(state bytea, signature bytea, key bytea) -> boolean
```

Aggregates:
```
    crypto_sign_update_agg(message bytea) -> bytea

    crypto_sign_update_agg(state, bytea message bytea) -> bytea
```

These functions are used to authenticate that messages have have come
from a specific originator (the holder of the secret key for which you
have the public key), and have not been tampered with.

`crypto_sign_new_keypair()` returns a new, randomly generated, pair of
keys for public key signatures.  The public key can be shared with
anyone.  The secret key must never be shared.

`crypto_sign()` and `crypto_sign_verify()` operate in combined mode.
In this mode the message that is being signed is combined with its
signature as a single unit.

`crypto_sign()` creates a signature, using the signer's secret key,
which it prepends to the message.  The result can be authenticated
using `crypto_sign_open()`.

`crypto_sign_open()` takes a signed message created by
`crypto_sign()`, checks its validity using the sender's public key and
returns the original message if it is valid, otherwise raises a data
exception.

`crypto_sign_detached()` and `crypto_sign_verify_detached()` operate
in detached mode.   In this mode the message is kept independent from
its signature.  This can be useful when wishing to sign objects that
have already been stored, or where multiple signatures are desired for
an object.

`crypto_sign_detached()` generates a signature for message using the
signer's secret key.  The result is a signature which exists
independently of the message, which can be verified using
`crypto_sign_verify_detached()`.

`crypto_sign_verify_detached()` is used to verify a signature
generated by `crypto_sign_detached()`.  It takes the generated
signature, the original message, and the signer's public key and
returns true if the signature matches the message and key, and false
otherwise.

`crypto_sign_init()`, `crypto_sign_update()`,
`crypto_sign_final_create()`, `crypto_sign_final_verify()`, and the
aggregates `crypto_sign_update_agg()` handle signatures for
multi-part messages.  To create or verify a signature for a multi-part
message `crypto_sign_init()` is used to start the process, and then each
message-part is passed to `crypto_sign_update()` or
`crypto_sign_update_agg()`.  Finally the signature is generated using
`crypto_sign_final_update()` or verified using
`crypto_sign_final_verify()`.

`crypto_sign_init()` creates an initial state value which will be
passed to `crypto_sign_update()` or `crypto_sign_update_agg()`.

`crypto_sign_update()` or `crypto_sign_update_agg()` will be used to
update the state for each part of the multi-part message.
`crypto_sign_update()` takes as a parameter the state returned from
`crypto_sign_init()` or the preceding call to `crypto_sign_update()`
or `crypto_sign_update_agg()`.  `crypto_sign_update_agg()` has two
variants: one takes a previous state value, allowing multiple
aggregates to be processed sequentially, and one takes no state
parameter, initialising the state itself.  Note that the order in
which the parts of a multi-part message are processed is critical.
They must be processed in the same order for signing and verifying.

`crypto_sign_final_update()` takes the state returned from the last
call to `crypto_sign_update()` or `crypto_sign_update_agg()` and the
signer's secret key and produces the final signature.  This can be
checked using `crypto_sign_final_verify()`.

`crypto_sign_final_verify()` is used to verify a multi-part message
signature created by `crypto_sign_final_update()`.  It must be
preceded by the same set of calls to `crypto_sign_update()` or
`crypto_sign_update_agg()` (with the same message-parts, in the same
order) that were used to create the signature.  It takes the state
returned from the last such call, along with the signature and the
signer's public key and returns true if the messages, key and
signature all match.

To sign or verify multi-part messages in SQL, CTE (Common Table
Expression) queries are particularly effective.  For example to sign a
message consisting of a timestamp and several message_parts:

```.sql
with init as
  (
    select crypto_sign_init() as state
  ),
timestamp_part as
  (
    select crypto_sign_update(i.state, m.timestamp::bytea) as state
      from init i
     cross join messages m
     where m.message_id = 42
  ),
remaining_parts as
  (
    select crypto_sign_update(t.state, p.message_part::bytea) as state
      from timestamp_part t
     cross join (
       select message_part
         from message_parts
        where message_id = 42
        order by message_part_num) p
  )
select crypto_sign_final_create(r.state, k.secret_key) as sig
  from remaining_parts r
 cross join keys k
 where k.key_name = 'xyzzy';
```

Note that storing secret keys in a table, as is done in the example
above, is a bad practice unless you have effective row-level security
in place.

[C API
Documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)

### Sealed boxes

Sealed boxes are designed to anonymously send messages to a recipient
given its public key.  Only the recipient can decrypt these messages,
using its private key. While the recipient can verify the integrity of
the message, it cannot verify the identity of the sender.

    SELECT public, secret FROM crypto_box_new_keypair() \gset bob_

    SELECT crypto_box_seal('bob is your uncle', :'bob_public') sealed \gset

The `sealed` psql variable is now the encrypted sealed box.  To unseal
it, bob needs his public and secret key:

    SELECT is(crypto_box_seal_open(:'sealed', :'bob_public', :'bob_secret'),
              'bob is your uncle', 'crypto_box_seal/open');


[C API Documentation](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)

## Hashing

This API computes a fixed-length fingerprint for an arbitrary long message.
Sample use cases:

  - File integrity checking
  - Creating unique identifiers to index arbitrary long data

The `crypto_generichash` and `crypto_shorthash` functions can be used
to generate hashes.  `crypto_generichash` takes an optional hash key
argument which can be NULL. In this case, a message will always have
the same fingerprint, similar to the MD5 or SHA-1 functions for which
crypto_generichash() is a faster and more secure alternative.

But a key can also be specified. A message will always have the same
fingerprint for a given key, but different keys used to hash the same
message are very likely to produce distinct fingerprints.  In
particular, the key can be used to make sure that different
applications generate different fingerprints even if they process the
same data.

    SELECT is(crypto_generichash('bob is your uncle'),
              '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
              'crypto_generichash');

    SELECT is(crypto_generichash('bob is your uncle', NULL),
              '\x6c80c5f772572423c3910a9561710313e4b6e74abc0d65f577a8ac1583673657',
              'crypto_generichash NULL key');

    SELECT is(crypto_generichash('bob is your uncle', 'super sekret key'),
              '\xe8e9e180d918ea9afe0bf44d1945ec356b2b6845e9a4c31acc6c02d826036e41',
              'crypto_generichash with key');

Many applications and programming language implementations were
recently found to be vulnerable to denial-of-service attacks when a
hash function with weak security guarantees, such as Murmurhash 3, was
used to construct a hash table .

In order to address this, Sodium provides the crypto_shorthash()
function, which outputs short but unpredictable (without knowing the
secret key) values suitable for picking a list in a hash table for a
given key.  This function is optimized for short inputs.  The output
of this function is only 64 bits. Therefore, it should not be
considered collision-resistant.

Use cases:

- Hash tables Probabilistic
- data structures such as Bloom filters
- Integrity checking in interactive protocols

Example:

    SELECT is(crypto_shorthash('bob is your uncle', 'super sekret key'),
              '\xe080614efb824a15',
              'crypto_shorthash');


[C API Documentation](https://doc.libsodium.org/hashing)

## Password hashing

    SELECT lives_ok($$SELECT crypto_pwhash_saltgen()$$, 'crypto_pwhash_saltgen');

    SELECT is(crypto_pwhash('Correct Horse Battery Staple', '\xccfe2b51d426f88f6f8f18c24635616b'),
            '\x77d029a9b3035c88f186ed0f69f58386ad0bd5252851b4e89f0d7057b5081342',
            'crypto_pwhash');

    SELECT ok(crypto_pwhash_str_verify(crypto_pwhash_str('Correct Horse Battery Staple'),
              'Correct Horse Battery Staple'),
              'crypto_pwhash_str_verify');


[C API Documentation](https://doc.libsodium.org/password_hashing)

## Key Derivation

Multiple secret subkeys can be derived from a single primary key.
Given the primary key and a key identifier, a subkey can be
deterministically computed. However, given a subkey, an attacker
cannot compute the primary key nor any other subkeys.

    SELECT crypto_kdf_keygen() kdfkey \gset
    SELECT length(crypto_kdf_derive_from_key(64, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
    SELECT is(:kdfsubkeylen, 64, 'kdf byte derived subkey');

    SELECT length(crypto_kdf_derive_from_key(32, 1, '__auth__', :'kdfkey')) kdfsubkeylen \gset
    SELECT is(:kdfsubkeylen, 32, 'kdf 32 byte derived subkey');

    SELECT is(crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'),
        crypto_kdf_derive_from_key(32, 2, '__auth__', :'kdfkey'), 'kdf subkeys are deterministic.');

[C API Documentation](https://doc.libsodium.org/key_derivation)

## Key Exchange

Using the key exchange API, two parties can securely compute a set of
shared keys using their peer's public key and their own secret key.

    SELECT crypto_kx_new_seed() kxseed \gset

    SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_bob_
    SELECT public, secret FROM crypto_kx_seed_new_keypair(:'kxseed') \gset seed_alice_

    SELECT tx, rx FROM crypto_kx_client_session_keys(
        :'seed_bob_public', :'seed_bob_secret',
        :'seed_alice_public') \gset session_bob_

    SELECT tx, rx FROM crypto_kx_server_session_keys(
        :'seed_alice_public', :'seed_alice_secret',
        :'seed_bob_public') \gset session_alice_

    SELECT crypto_secretbox('hello alice', :'secretboxnonce', :'session_bob_tx') bob_to_alice \gset

    SELECT is(crypto_secretbox_open(:'bob_to_alice', :'secretboxnonce', :'session_alice_rx'),
              'hello alice', 'secretbox_open session key');

    SELECT crypto_secretbox('hello bob', :'secretboxnonce', :'session_alice_tx') alice_to_bob \gset

    SELECT is(crypto_secretbox_open(:'alice_to_bob', :'secretboxnonce', :'session_bob_rx'),
              'hello bob', 'secretbox_open session key');


[C API Documentation](https://doc.libsodium.org/key_exchange)

## HMAC512/256

[https://en.wikipedia.org/wiki/HMAC]

In cryptography, an HMAC (sometimes expanded as either keyed-hash
message authentication code or hash-based message authentication code)
is a specific type of message authentication code (MAC) involving a
cryptographic hash function and a secret cryptographic key. As with
any MAC, it may be used to simultaneously verify both the data
integrity and authenticity of a message.

    select crypto_auth_hmacsha512_keygen() hmac512key \gset
    select crypto_auth_hmacsha512('food', :'hmac512key') hmac512 \gset

    select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'hmac512key'), true, 'hmac512 verified');
    select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'hmac512key'), false, 'hmac512 not verified');

[C API Documentation](https://doc.libsodium.org/advanced/hmac-sha2)

## Advanced Stream API (XChaCha20)

The stream API is for advanced users only and only provide low level
encryption without authentication.

[C API Documentation](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20)

## XChaCha20-SIV

Deterministic/nonce-reuse resistant authenticated encryption scheme
using XChaCha20.

[C API Documentation](https://github.com/jedisct1/libsodium-xchacha20-siv)

## SignCryption

Traditional authenticated encryption with a shared key allows two or
more parties to decrypt a ciphertext and verify that it was created by
a member of the group knowing that secret key.

However, [it doesn't allow
verification](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html)
of who in a group originally created a message.

In order to do so, authenticated encryption has to be combined with
signatures.

The Toorani-Beheshti signcryption scheme achieves this using a single
key pair per device, with forward security and public verifiability.

[C API Documentation](https://github.com/jedisct1/libsodium-signcryption)
