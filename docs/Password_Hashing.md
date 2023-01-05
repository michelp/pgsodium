# Password Hashing

Secret keys used to encrypt or sign confidential data have to be chosen from a very large keyspace.

However, passwords are usually short, human-generated strings, making dictionary attacks practical.

Password hashing functions derive a secret key of any size from a password and salt.

  - The generated key has the size defined by the application, no matter what the password length is.
  - The same password hashed with the same parameters will always produce the same output.
  - The same password hashed with different salts will produce different outputs.
  - The function deriving a key from a password and salt is CPU intensive and intentionally requires a fair amount of memory. Therefore, it mitigates brute-force attacks by requiring a significant effort to verify each password.
  
Common use cases:

  - Password storage, or rather storing what it takes to verify a password without having to store the actual password.
  - Deriving a secret key from a password; for example, for disk encryption.
  
Sodium's high-level crypto_pwhash_* API currently leverages the Argon2id function on all platforms. This can change at any point in time, but it is guaranteed that a given version of libsodium can verify all hashes produced by all previous versions from any platform. Applications don't have to worry about backward compatibility.


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



### `crypto_pwhash_saltgen()`


```python
salt = %sql select pgsodium.crypto_pwhash_saltgen()
salt = salt[0][0].tobytes()
print(salt)
```

    b'@\xb0\x86\x1c\xcb9\xf0\x03\xfb\x91xt\r\xad\xffG'


### `crypto_pwhash(password bytea, salt bytea)`


```python
hash = %sql select pgsodium.crypto_pwhash('Correct Horse Battery Staple', :salt)
hash = hash[0][0].tobytes()
print(hash)
```

    b'!\xd6\x11\xab\xdey\xdc\x93.\xb1a7\xd8\xf1Q\xc7\xc4f\xc0\xc0\xa0\x96\xbe<(\xa3(\x87\x1a\x11(='


### `crypto_pwhash_str(password bytea)`


```python
hash = %sql select pgsodium.crypto_pwhash_str('Correct Horse Battery Staple')::text
hash = hash[0][0]
print(hash)
```

    \x246172676f6e32696424763d3139246d3d3236323134342c743d332c703d312437654669655843796f6f736e734736626c42514856672437726a6f6c6c757058596643557838464f494948745651434268643644486d6738707a446f767934493638000000000000000000000000000000000000000000000000000000000000


### `crypto_pwhash_str_verify(hash bytea, password bytea)`


```python
result = %sql select pgsodium.crypto_pwhash_str_verify((:hash)::bytea, 'Correct Horse Battery Staple')
print(result)
```

    +--------------------------+
    | crypto_pwhash_str_verify |
    +--------------------------+
    |           True           |
    +--------------------------+

