## Hash-based Message Authentication Codes

[https://en.wikipedia.org/wiki/HMAC]

In cryptography, an HMAC (sometimes expanded as either keyed-hash
message authentication code or hash-based message authentication code)
is a specific type of message authentication code (MAC) involving a
cryptographic hash function and a secret cryptographic key. As with
any MAC, it may be used to simultaneously verify both the data
integrity and authenticity of a message.

[C API Documentation](https://doc.libsodium.org/advanced/hmac-sha2)

pgsodium provides hmacsha512 and hmacsha256, only 512-bit examples are provided below, the 256-bit API is identical but using names like `crypto_auth_hmacsha256_*`.



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



### `crypto_auth_hmacsha512_keygen()`


```python
key = %sql select pgsodium.crypto_auth_hmacsha512_keygen()
key = key[0][0].tobytes()
print(key)
```

    b'|\'\x88\xf1\x88\x82\x8b\xcb"O\x1a\'\xb8#c\xa6f\x1ag\x05nx5\xc2\xe5u8</\xa0\xbd\x18'


### `crypto_auth_hmacsha512(message bytea, key bytea)`


```python
signature = %sql select pgsodium.crypto_auth_hmacsha512('this is authentic', :key)
signature = signature[0][0].tobytes()
print(signature)
```

    b'2\xae\x9d_\xb2\xaf\xf1\x08tq2\x97V*\xb1\x10\xb6b\xb1s\xcc\x06\x95\x12\x9f\xfb\xbc\x07-L]m\x88\\\x80\x98\x8cHc\xbd\x96\xe5\xb1\xd9{\x17\x1eP\x11^\xc3\x1f\x89\xb7\xacL&\x12\xd7\xefr\xe7j8'


### `crypto_auth_hmacsha512_verify(signature bytea, message bytea, key bytea)`


```python
verify = %sql select pgsodium.crypto_auth_hmacsha512_verify(:signature, 'this is authentic', :key)
print(verify)
```

    +-------------------------------+
    | crypto_auth_hmacsha512_verify |
    +-------------------------------+
    |              True             |
    +-------------------------------+

