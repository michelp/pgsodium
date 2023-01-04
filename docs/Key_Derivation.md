# Key Derivation

Multiple secret subkeys can be derived from a single master key.

Given the master key and a key identifier, a subkey can be deterministically computed. However, given a subkey, an attacker cannot compute the master key nor any other subkeys.

The crypto_kdf API can derive up to 2^64 keys from a single master key and context, and individual subkeys can have an arbitrary length between 128 (16 bytes) and 512 bits (64 bytes).


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



### `derive_key(id integer, key_size integer = NULL, context bytea = 'pgsodium')`


```python
key = %sql select pgsodium.derive_key(42)
print(key[0][0].tobytes())
```

    b'\xfd\x95 Q%\x16\x9f\xca5\xac\x18\xf3\x8az\x98\x9f\x11fD\x14\x04|\x02Q\xe5M\xbe\xf7\x82\xf3|<'



```python
key = %sql select pgsodium.derive_key(42, 64, 'foozbarz')
print(key[0][0].tobytes())
```

    b'\xad\xeeu\x1d\x1d\xc3H\xad\x01\x19\xff\x1alO\x1e\xf9e-\xe2\xf9\x8b\x9a\x97>P\x85\x83C\x9b$\x04U!2+&\xc4\xdb\x7f\x07\xb4\x17\xdf,\x95\xdce\xa5x\xb7A\xaeG\xc1=\xff~N\xdf\xa1\xfdc\xf4J'

