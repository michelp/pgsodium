# Configuration

pgsodium can be used in two ways:

- either as a "pure" library extension with no server managed keys that you can load into your SQL session at any time with the `LOAD` command

- "preload" mode where you place `pgsodium` in your postgres server's `shared_preload_libraries` configuration variable.

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
need to provide your own key management.  

See the file
[`../getkey_scripts/pgsodium_getkey_urandom.sh`](../getkey_scripts/pgsodium_getkey_urandom.sh)
for an example script that returns a libsodium key using the linux
`/dev/urandom` CSPRNG.

pgsodium also comes with example scripts for:

  - [Amazon Web Service's Key Management
    Service](../getkey_scripts/pgsodium_getkey_aws.sh).

  - [Google Cloud's Cloud Key
    Management](../getkey_scripts/pgsodium_getkey_gcp.sh).

  - [Doppler SecretOps Platform](../getkey_scripts/pgsodium_getkey_doppler.sh).

  - [Zymbit Zymkey 4i Hardware Security
    Module](../getkey_scripts/pgsodium_getkey_zmk.sh).

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


