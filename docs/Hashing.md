# Generic and Short Hashing

libsodium provides functions for "generic" and "short" hashing.  

Generic hashing is suitable for cryptographic purposes using the BLAKE2b algorithm.


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



### `crypto_generichash_keygen()`


```python
k = %sql select pgsodium.crypto_generichash_keygen()
generichash_key = k[0][0].tobytes()
print(generichash_key)
```

    b'\xf2\xcc\xc18\x8f)\x93\x0b^\x12\x13\xa3q\x9e\x83\x03\xb7\xb0\xe9z+/\x1b\xd4\xae\x1fO\xa4pj\xab\xef'


### `crypto_generichash(message bytea, key bytea = NULL)`


```python
signature = %sql select pgsodium.crypto_generichash('this is a message')
print(signature[0][0].tobytes())
```

    b'\x9dJc\xe5\xdc\x1dw\xed\x99\xb6\xf7V\x92\x0e\xdb\x89\xdf\xda\xd2|J!\xf2\xa9j\x85\x82K\x8f\xdb_\xe1'



```python
signature = %sql select pgsodium.crypto_generichash('this is a message', :generichash_key)
print(signature[0][0].tobytes())
```

    b'Y\xc6"\x97\xa5\x16\xa4\xa3\xaay8\xe4\xad)XS\xa1~UDO)X\x0bl\x82\xa0\x87\xba|\x1al'


## Short Hashing

Many applications and programming language implementations were recently found to be vulnerable to denial-of-service (DoS) attacks when a hash function with weak security guarantees, such as MurmurHash3, was used to construct a hash table.

To address this, Sodium provides the crypto_shorthash() function, which outputs short but unpredictable (without knowing the secret key) values suitable for picking a list in a hash table for a given key.

This function is optimized for short inputs.

The output of this function is only 64 bits. Therefore, it should not be considered collision-resistant.

Use cases:
- Hash tables
- Probabilistic data structures, such as Bloom filters
- Integrity checking in interactive protocols

### `crypto_shorthash_keygen()`


```python
k = %sql select pgsodium.crypto_shorthash_keygen()
shorthash_key = k[0][0].tobytes()
print(shorthash_key)
```

    b'%\x9a\xedN\xad\xa3\xf5php\xa5\x93\rd\xe3\xa2'


### `crypto_shorthash(message bytea, key bytea)`


```python
short_signature = %sql select pgsodium.crypto_shorthash('this is a message', :shorthash_key)
print(short_signature[0][0].tobytes())
```

    b'\xb1\xfd\xa4VAjg\xcc'

