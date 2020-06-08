
[![Build Status](https://api.travis-ci.com/michelp/pgsodium.svg?branch=master)](https://travis-ci.com/github/michelp/pgsodium)
<br />
# pgsodium

pgsodium is a [PostgreSQL](https://www.postgresql.org/) extension that
exposes modern [libsodium](https://download.libsodium.org/doc/) based
cryptographic functions to SQL.

## Installation

[Travis CI](https://travis-ci.com/github/michelp/pgsodium) tested with
the [official docker images](https://hub.docker.com/_/postgres) for
PostgreSQL 13, 12, 11, and 10.  Requires libsodium >= 1.0.18.  In
addition to the libsodium library and it's development headers, you
may also need the postgres header files typically in the '-dev'
packages to build the extension.

Clone the repo and run 'sudo make install'.

pgTAP tests can be run with 'sudo -u postgres pg_prove test.sql' or
they can be run in a self-contained Docker image.  Run `./test.sh` if
you have docker installed to run all tests.  Note that this will run
the tests against and download docker imags for four different major
versions of postgresql, so it takes a while and requires a lot of
network bandwidth the first time you run it.

# Usage

pgsodium arguments and return values for content and keys are of type
`bytea`.  If you wish to use `text` or `varchar` values for general
content, you must make sure they are encoded correctly.  The
[`encode() and decode()` and
`convert_to()/convert_from()`](https://www.postgresql.org/docs/12/functions-binarystring.html)
binary string functions can convert from `text` to `bytea`.Simple
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
allocated memory used by the when freed.  In general it is a bad idea
to store secrets in the database itself, although this can be done
carefully it has a higher risk.  To help with this problem, pgsodium
has an optional Server Key Management function that can load a server
key at boot.

# Server Key Management

If you add pgsodium to your `shared_preload_libraries` configuration
and place a special script in your postgres shared extension
directory, the server can preload a libsodium keypair on server start.

This is completely optional, pgsodium can still be used without
putting it in `shared_preload_libraries`, you will simply need to
provide your own key management.  Skip ahead to the API usage section
if you choose not to use server managed keys.

See the file `pgsodium_getkeypair.sample` for an example script that
returns a libsodium key.  The script must emit a hex encoded 32 byte
(64 character) string on a single line.  DO NOT USE THIS FILE WITHOUT
SUBSTITUTING YOUR OWN KEY.  Edit the file to add your own key and
remove the `exit` line, remove the `.sample` suffix and make the file
executable (on unixen `chmod +x pgsodium_getkeypair`).

Next place `pgsodium` in your `shared_preload_libraries`.  For docker
containers, you can append this after the run:

    docker run -e POSTGRES_HOST_AUTH_METHOD=trust -d --name "$DB_HOST" $TAG -c 'shared_preload_libraries=pgsodium'

When the server starts, it will load the secret key into memory.

    postgres=# show pgsodium.secret_key ;
                           pgsodium.secret_key
    ------------------------------------------------------------------
     ****************************************************************

    postgres=# select current_setting('pgsodium.secret_key');
                             current_setting
    ------------------------------------------------------------------
     ****************************************************************

The secret key **cannot be accessed from sql**, ever.  It is up to you
to edit the script to get or generate the key however you want.
Common patterns including prompting for the keys on boot, fetching
them from an ssh server or managed cloud secret system, or using a
command line tool to get them from a hardware security module.

# Server Key Derivation

If you choose to use server managed keys described above, pgsodium
provides function for deriving new keys from the server key.  You
cannot access the server secret key directly, you must derive a key
from it to use.  If you choose not to use server managed keys, skip
ahead to the API section.

pgsodium lets you derive new secret keys from the master server secret
key by id and an optional context using the [libsodium Key Derivation
Functions](https://doc.libsodium.org/key_derivation).  Key id are just
`bigint` integers.  If you know the key id and the context, you can
ask the system for the derived key.  You can now use this key to
encrypt data.  If an attacker steals your database image, they cannot
generate the key even if they know the key id and context without the
server secret key.

The key id can be secret or not, if you store the key id then logged
in users can generate the key if they know the key length and context.
Keeping the key id secret to a client avoid this possibility and make
sure to set your database security model correctly so that only the
minimum permission possible is given to users that interact with the
encryption API.

Key rotation can be as simple as incrementing the key id and
re-encrypting from N to N+1.  Frequent rotation means even if an
attacker acquires a ancestor key, it will not work to decrypt data
generated with a successor key.

A context is an 8 byte `bytea`. The same key id in different contexts
generate different keys.  The default context is the ascii encoded
bytes `pgsodium`.  You are free to use any 8 bytes context to scope
your keys, but remember it must be an 8 byte `bytea`, not an 8
character text or varchar, see the [`encode() and decode()` and
`convert_to()/convert_from()`](https://www.postgresql.org/docs/12/functions-binarystring.html)
binary string functions.  The derivable keyspace is huge given one
`bigint` keyspace per context and 2^64 contexts.

To derive a key, call:

    select pgsodium_derive(key_id bigint);
    
    select pgsodium_derive(key_id bigint, 64);
    
    select pgsodium_derive(key_id bigint, 64, 'username');
    
The default keysize is `32` and the default context is
`'pgsodium'`.

Derived keys can be used either directy in `crypto_secretbox_*`
functions or as seeds for generating other keypairs using for example
`crypto_box_seed_keypair()` and `crypto_sign_seed_keypair()`.

# Simple public key encryption with `crypto_box()`

Here's an example usage from the test.sql that uses command-line
[`psql`](https://www.postgresql.org/docs/12/app-psql.html) client
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
are *interpolated* into the sql that is sent to the server, so it's
possible they can show up in the database logs.

# Avoid secret logging

A more paranoid approach is to keep keys in an external storage and
disables logging while injecting the keys into local variables with
[`SET LOCAL`](https://www.postgresql.org/docs/12/sql-set.html). If the
images of database are hacked or stolen, the keys will not be
available to the attacker.

To disable logging of the key injections, `SET LOCAL` is also used to
disable
[`log_statements`](https://www.postgresql.org/docs/12/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT)
and then re-enable normal logging afterwards. as shown below. Setting
`log_statement` requires superuser privledges:

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

For more paranoia you can use a function to check that the connection
being used is secure or a unix domain socket.

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
`psql` client `\gset` command shown above.

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

    postgres=# select randombytes_random();
     randombytes_random
    --------------------
             1229887405
    (1 row)

The `randombytes_random()` function returns an unpredictable value
between 0 and 0xffffffff (included).

    postgres=# select randombytes_uniform(42);
     randombytes_uniform
    ---------------------
                      23
    (1 row)

The `randombytes_uniform()` function returns an unpredictable value
between `0` and `upper_bound` (excluded). Unlike `randombytes_random() %
upper_bound`, it guarantees a uniform distribution of the possible
output values even when `upper_bound` is not a power of 2. Note that an
`upper_bound < 2` leaves only a single element to be chosen, namely 0.

    postgres=# select randombytes_buf(42);
                                        randombytes_buf
    ----------------------------------------------------------------------------------------
     \x27cec8d2c3de16317074b57acba2109e43b5623e1fb7cae12e8806daa21a72f058430f22ec993986fcb2
    (1 row)

The `randombytes_buf()` function returns a `bytea` with an
unpredictable sequence of bytes.

    postgres=# select randombytes_new_seed() bufseed \gset
    postgres=# select randombytes_buf_deterministic(42, :'bufseed');
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
nonce and secret key.  The encrypted message can be decrypted using
`crypto_secretbox_open()`  Note that in order to decrypt the message,
the original nonce will be needed.

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

`crypto_box_open()` descrypts a ciphertext encrypted using
`crypto_box()`.  It takes the ciphertext, nonce, the sender's public
key and the recipeient's secret key as parameters, and returns the
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
`crypto_sign_final_update()` or verfified using
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
parameter, initiialising the state itself.  Note that the order in
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

## Hashing

## Password hashing

## Key Derivation

## Key Exchange

## Advanced

### HMAC512
