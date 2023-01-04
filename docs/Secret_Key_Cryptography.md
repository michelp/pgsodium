# Secret Key Cryptography


```python
%load_ext sql
```


```python
%config SqlMagic.feedback=False
%config SqlMagic.displaycon=False
%sql postgresql://postgres@/
```


```sql
%%sql 
CREATE EXTENSION IF NOT EXISTS pgsodium;
```




    []



## Authenticated Encryption

### `crypto_secretbox_keygen()`


```python
key = %sql select pgsodium.crypto_secretbox_keygen()
key = key[0][0].tobytes()
print(key)
```

    b"\xb7\x8e\x1f\xefc\xc8\xaa\x9b\xd45\xa5\xf2\x14'\n\xeb\x82\x9a\x945\x07Z}\xf33\x17JA\x84\xa7}f"


### `crypto_secretbox_noncegen()`


```python
nonce = %sql select pgsodium.crypto_secretbox_noncegen()
nonce = nonce[0][0].tobytes()
print(nonce)
```

    b'\x08\xa8\xf4O\xfe8\x03\xd5\x02\x8b\x9e\xce\n*\xe8\xec\x02U\x00x(\xe0\x1d\xea'


### `crypto_secretbox(message bytea, nonce bytea, key bytea)`


```python
ciphertext = %sql select pgsodium.crypto_secretbox('bob is your uncle', :nonce, :key)
ciphertext = ciphertext[0][0].tobytes()
print(ciphertext)
```

    b'\n!\x03\xa1x\n\xdd<*\xa07o\xde\xcb,"t\xce\xa1\xb0\x13nX\xf9#q\xe8\xedo\x19~.\xb0'


### `crypto_secretbox_open(ciphertext bytea, nonce bytea, key bytea)`


```python
message = %sql select pgsodium.crypto_secretbox_open(:ciphertext, :nonce, :key)
message = message[0][0].tobytes()
print(message)
```

    b'bob is your uncle'

