
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
carefully it has a higher risk.

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
and then re-enable normal logging afterwards. as shown below:

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

# API Reference

The reference below is adapted from and uses some of the same language
found at the [libsodium C API
Documentation](https://doc.libsodium.org/).  Refer to those documents
for details on algorithms and other libsodium specific details.

The libsodium documentation is Copyright (c) 2014-2018, Frank Denis
<github@pureftpd.org> and released under [The ISC
License](https://github.com/jedisct1/libsodium-doc/blob/master/LICENSE).

## Generating Random Data

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

### Authenticated encryption

### Authentication

## Public key cryptography

### Authenticated encryption

### Public key signatures

### Sealed boxes

## Hashing

## Password hashing

## Key Derivation

## Key Exchange

## Advanced

### HMAC512
