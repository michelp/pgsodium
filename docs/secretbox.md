``` postgres-console
NOTICE:  extension "pgsodium" already exists, skipping
```
# Secret Key Cryptography
``` postgres-console
select pgsodium.crypto_secretbox_keygen() key \gset
select pgsodium.crypto_secretbox_noncegen() nonce \gset
select pgsodium.crypto_secretbox('bob is your uncle', :'nonce', :'key') secretbox \gset
ERROR:  function pgsodium.crypto_secretbox(unknown, unknown, unknown) is not unique
LINE 1: select pgsodium.crypto_secretbox('bob is your uncle',  E'\\x...
               ^
HINT:  Could not choose a best candidate function. You might need to add explicit type casts.
select pgsodium.crypto_secretbox_open(:'secretbox', :'nonce', :'key');
ERROR:  syntax error at or near ":"
LINE 1: select pgsodium.crypto_secretbox_open(:'secretbox',  E'\\xaf...
                                              ^
```