``` postgres-console
NOTICE:  extension "pgsodium" already exists, skipping
```
# Key Exchange

Using the key exchange API, two parties can securely compute a set of
shared keys using their peer's public key and their own secret key
``` postgres-console
select public, secret from pgsodium.crypto_kx_new_keypair() \gset bob_
select public, secret from pgsodium.crypto_kx_new_keypair() \gset alice_
select tx, rx from pgsodium.crypto_kx_client_session_keys(:'bob_public'::bytea, :'bob_secret'::bytea, :'alice_public'::bytea);
┌────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────┐
│                                 tx                                 │                                 rx                                 │
├────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────┤
│ \x409d04d77c9b1e05baa3eea9a78be848f8c88157b20abbe0a4d84dd8052e6e8c │ \xcf31bc31458d176fc780447186c17ec43a69cd2a99e2c143411e582fd32936c1 │
└────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────────┘
(1 row)

select tx, rx from pgsodium.crypto_kx_server_session_keys(:'alice_public'::bytea, :'alice_secret'::bytea, :'bob_public'::bytea)
┌────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────┐
│                                 tx                                 │                                 rx                                 │
├────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────┤
│ \xcf31bc31458d176fc780447186c17ec43a69cd2a99e2c143411e582fd32936c1 │ \x409d04d77c9b1e05baa3eea9a78be848f8c88157b20abbe0a4d84dd8052e6e8c │
└────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────────┘
(1 row)

```