# pgsodium

Postgres extension for [libsodium](https://download.libsodium.org/doc/).

## Installation

Tested with Postgres 11.5, but has and should work with 10 and 9.6.
Recommend libsodium >= 1.0.18 but has and should work with >= 1.0.16.
If your operating system provides packages you may also need the
header files typically in the '-dev' package.

Clone the repo and run 'sudo make install'.

pgTAP tests can be run with 'sudo -u postgres pg_prove test.sql' or
they can be run in a self-contained Docker test image by running
`./test.sh` if you have docker installed.

## Usage

Most of the libsodium API is available.  Keys that are generated in
pairs are returned as a record type, for example:

```
postgres=# SELECT * FROM crypto_box_new_keypair();
                               public                               |                               secret
--------------------------------------------------------------------+--------------------------------------------------------------------
 \xa55f5d40b814ae4a5c7e170cd6dc0493305e3872290741d3be24a1b2f508ab31 | \x4a0d2036e4829b2da172fea575a568a74a9740e86a7fc4195fe34c6dcac99976
(1 row)
```

Here's an example usage from the test.sql file:

```
-- Generate a boxnonce, and public and secret keypairs for bob and alice
SELECT crypto_box_noncegen() boxnonce \gset
SELECT public, secret FROM crypto_box_new_keypair() \gset bob_
SELECT public, secret FROM crypto_box_new_keypair() \gset alice_

-- Alice encrypts the box for bob using her secret key and his public key
SELECT crypto_box('bob is your uncle', :'boxnonce', :'bob_public', :'alice_secret') box \gset

-- Bob decrypts the box using his secret key and Alice's public key
SELECT is(crypto_box_open(:'box', :'boxnonce', :'alice_public', :'bob_secret'),
          'bob is your uncle', 'crypto_box_open');
```
